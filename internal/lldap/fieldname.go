package lldap

import "strings"

// LLDAP v0.6.3 refuses '_' in attribute names (validate_attribute_name,
// crates/validation/src/attributes.rs: a-z, A-Z, 0-9 and '-'), while
// custom field names (contract §4.1) use '_' and never '-'. A field's LLDAP
// attribute is therefore the field name with '_' → '-'. These two
// functions are the only place the mapping happens: everything the Hub
// sends to or reads from LLDAP for a custom field goes through them.

// FieldAttrName is the LLDAP attribute of custom field field.
func FieldAttrName(field string) string { return strings.ReplaceAll(field, "_", "-") }

// FieldFromAttrName is the custom field an LLDAP attribute carries; false
// when attr can't be one (it contains '_', which no mapped name has).
// Callers still check the result against the defined fields.
func FieldFromAttrName(attr string) (string, bool) {
	if strings.Contains(attr, "_") {
		return "", false
	}
	f := strings.ReplaceAll(attr, "-", "_")
	return f, FieldAttrName(f) == attr
}
