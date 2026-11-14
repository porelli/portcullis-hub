package kube

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// CoreNamespace is the core namespace's name label value (the API
// server sets kubernetes.io/metadata.name: it can't be forged).
const CoreNamespace = "portcullis"

// nsLabel is the API server's namespace name label.
const nsLabel = "kubernetes.io/metadata.name"

// PolicyInput are the facts InstancePolicies needs beyond the plan.
type PolicyInput struct {
	Instance  string
	Namespace string
	// CoreNamespace is PORTCULLIS_NAMESPACE (default portcullis).
	CoreNamespace string
	// RoutedPorts: compose service → container ports Traefik routes;
	// CompanionPorts: those mcp-gate calls (§3.2).
	RoutedPorts, CompanionPorts map[string][]int
	// Networks: compose network → its member services; Egress the
	// services on a non-internal network.
	Networks map[string][]string
	Egress   []string
	// Pods: compose service → the service whose pod runs it.
	Pods     map[string]string
	Settings Settings
	// VPNService / VPNSlot: a wired gateway's ingress service and slot.
	VPNService string
	VPNSlot    *int
}

// InstancePolicies are the instance's NetworkPolicies (contract §5
// "Routed ports open only to Traefik"): only these shapes, each with a
// podSelector on the instance's pods and peers that are its own pods,
// Traefik or mcp-gate (by pod labels in the core namespace), the egress
// ipBlock with its except list, the node 80/443 rule, kube-dns and the
// gateway's edge port. Never an empty selector or a rule without from/to.
func InstancePolicies(in PolicyInput) ([]*unstructured.Unstructured, error) {
	core := in.CoreNamespace
	if core == "" {
		core = CoreNamespace
	}
	var out []*unstructured.Unstructured
	add := func(name string, sel map[string]string, types []networkingv1.PolicyType, ing []networkingv1.NetworkPolicyIngressRule, eg []networkingv1.NetworkPolicyEgressRule) error {
		sel[LabelInstance] = in.Instance
		np := &networkingv1.NetworkPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
			ObjectMeta: metav1.ObjectMeta{Name: joinName(in.Instance, name, ""), Namespace: in.Namespace, Labels: map[string]string{LabelInstance: in.Instance}},
			Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: sel}, PolicyTypes: types, Ingress: ing, Egress: eg}}
		u, err := toUnstructured(np)
		if err != nil {
			return err
		}
		out = append(out, u)
		return nil
	}
	both := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}
	ingress := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	egress := []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	dns := intstr.FromInt32(53)
	// kube-dns on 53: in every per-network policy (each pod is on one;
	// the admission policy refuses a selector without a net/egress/
	// service/slot key).
	kubeDNS := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{nsLabel: "kube-system"}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
		}},
		Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
	}
	// Same-network peers within the instance.
	for _, n := range slices.Sorted(mapKeys(in.Networks)) {
		l := LabelNetPrefix + sanitize(n)
		peer := []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{LabelInstance: in.Instance, l: "true"}}}}
		if err := add("net-"+n, map[string]string{l: "true"}, both,
			[]networkingv1.NetworkPolicyIngressRule{{From: peer}}, []networkingv1.NetworkPolicyEgressRule{{To: peer}, kubeDNS}); err != nil {
			return nil, err
		}
	}
	corePeer := func(component string) []networkingv1.NetworkPolicyPeer {
		return []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{nsLabel: core}},
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{LabelComponent: component}},
		}}
	}
	portsOf := func(ps []int) []networkingv1.NetworkPolicyPort {
		var out []networkingv1.NetworkPolicyPort
		for _, p := range ps {
			v := intstr.FromInt32(int32(p))
			out = append(out, networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &v})
		}
		return out
	}
	for _, kind := range []struct {
		name, component string
		ports           map[string][]int
	}{{"routed", "traefik", in.RoutedPorts}, {"companion", "mcp-gate", in.CompanionPorts}} {
		for _, svc := range slices.Sorted(mapKeys(kind.ports)) {
			ps := slices.Clone(kind.ports[svc])
			slices.Sort(ps)
			ps = slices.Compact(ps)
			if len(ps) == 0 {
				continue
			}
			pod := svc
			if p, ok := in.Pods[svc]; ok {
				pod = p
			}
			if err := add(kind.name+"-"+svc, map[string]string{LabelService: sanitizeLabel(pod)}, ingress,
				[]networkingv1.NetworkPolicyIngressRule{{From: corePeer(kind.component), Ports: portsOf(ps)}}, nil); err != nil {
				return nil, err
			}
		}
	}
	// Internet egress for non-internal networks.
	if len(in.Egress) > 0 {
		except := []string{}
		for _, c := range []string{in.Settings.PodCIDR, in.Settings.ServiceCIDR, "169.254.0.0/16"} {
			if c != "" {
				except = append(except, c)
			}
		}
		if len(in.Settings.NodeAddresses) == 0 {
			return nil, refused("%s needs internet egress, and core.env has no node addresses (PORTCULLIS_KUBE_NODE_ADDRESSES): not deployed", in.Instance)
		}
		var nodes []networkingv1.NetworkPolicyPeer
		for _, a := range in.Settings.NodeAddresses {
			ip, err := netip.ParseAddr(strings.TrimSpace(a))
			if err != nil || !ip.Is4() {
				return nil, refused("node address %q is not an IPv4 address", a)
			}
			except = append(except, ip.String()+"/32")
			nodes = append(nodes, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: ip.String() + "/32"}})
		}
		https, http := intstr.FromInt32(443), intstr.FromInt32(80)
		if err := add("egress", map[string]string{LabelEgress: "true"}, egress, nil, []networkingv1.NetworkPolicyEgressRule{
			{To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: except}}}},
			{To: nodes, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &http}, {Protocol: &tcp, Port: &https}}},
		}); err != nil {
			return nil, err
		}
	}
	// A wired VPN gateway: its edge port on the wg pod only.
	if in.VPNSlot != nil {
		if *in.VPNSlot < 0 || *in.VPNSlot > 46 {
			return nil, refused("VPN slot %d is outside 0–46", *in.VPNSlot)
		}
		port := intstr.FromInt32(int32(9001 + *in.VPNSlot))
		if err := add("vpn-edge", map[string]string{LabelVPNSlot: fmt.Sprint(*in.VPNSlot)}, egress, nil, []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{nsLabel: core}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{LabelComponent: "wg"}},
			}},
			Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
		}}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
