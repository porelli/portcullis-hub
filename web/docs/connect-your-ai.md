# Connect Your AI

Use your Portcullis apps from Claude, Claude Code or another AI assistant,
**as yourself**. The AI signs in with your passkey, so it can see and change
only what you can, and deleting things always asks for your passkey in your
browser. This page is for the people using it; administrators set it up in
[AI support](../operations/ai.md).

You find everything on **`people.<domain>` → My apps → Connect your AI**. The
card appears only while your administrator has AI support on and you can use
at least one app (or your Portcullis account) through it.

![The Connect your AI card](../assets/ai/connect-your-ai-card.png)

## What the card shows

- **All my apps**: one address, `https://mcp.<domain>/mcp`, for every app you
  can use with AI, plus your Portcullis account. "Covers …" lists the apps it
  includes; apps added later join it on their own. Apps that sign you in
  themselves (Home Assistant) are connected separately.
- **One app only**: each app's own address, its mode (*read and write* or
  *read only*, your administrator's choice) and a *community* mark when the
  app's MCP server isn't the app project's own. **Steps** opens the
  instructions for that app alone.
- **Portcullis (administrators)**: only for administrators, while the admin
  MCP is enabled for at least one client: `https://hub.<domain>/mcp`.
- **Your AI connections** and **Recent AI activity** (below).

Each address has a **Copy** button, and the instructions come in tabs, one
per AI client your administrator offers.

## Claude desktop, claude.ai and Claude mobile

1. Open Claude → **Customize → Connectors → Add custom connector**.
   (Team or Enterprise plan: ask an Owner to add it in Organization settings
   → Connectors → Add → Custom → Web, then click Connect.)
2. Name: **Portcullis apps** (or the app's name), URL: the address from the
   card.
3. Open **Advanced settings** (or choose "Use your own OAuth client"):
   OAuth Client ID **`portcullis-ai-claude`**. Leave the client secret empty.
4. Click **Add**, then **Connect**. Sign in with your passkey and allow
   access.

Claude connects from Anthropic's servers, so this works only while your
Portcullis is reachable from the internet.

## Claude Code

Paste the command from the card in a terminal, for example:

```bash
claude mcp add --transport http --scope user --client-id portcullis-ai-claude-code \
  --callback-port 33418 portcullis-apps https://mcp.example.com/mcp
```

Then start Claude Code, type `/mcp`, choose `portcullis-apps` and sign in with
your passkey in the browser that opens. Keep `--callback-port 33418`: the
sign-in only accepts that port.

For a single app the server name is the app's name as the card shows it,
lowercased, with other characters turned into `-` (`gitea`). When two rows
would share a name, each gets its instance id added, then the companion name
if that is still not enough (two Gitea instances: `gitea-gitea` and
`gitea-gitea-b`).

## Other MCP clients

Server URL: the card's address · Transport: Streamable HTTP · OAuth: the
authorization server is discovered automatically (Keycloak at
`auth.<domain>`) · Client ID `portcullis-ai-generic` · no secret · PKCE S256 ·
redirect `http://localhost:33418/callback` · scope `mcp:all` for All my apps
(the card shows each app's own scope).

## Apps that sign you in themselves

Some apps (Home Assistant) are their own sign-in server for AI clients. The
card says "signs in with <app>":

- **Claude:** add it as a custom connector with "Use Claude's published
  identity"; the app asks you to sign in (passkey).
- **Claude Code:** `claude mcp add --transport http --scope user <name> <url>`,
  without a client id.

The app applies its own rules: Portcullis doesn't log or confirm its AI
actions.

## When the AI wants to delete something

Deleting, and a few other risky actions, need you in your browser. The AI
gives you a link (or your client opens it):

![A confirmation page](../assets/ai/confirmation-page.png)

1. Check the action, the target and the arguments: this is what will run,
   exactly.
2. Type the check the page asks for (the app's name, or for administrators
   the instance id or the person's name).
3. Approve with your passkey, then ask the AI to try again.

A confirmation is valid for 10 minutes and works once; Decline needs no
passkey. If the AI changes anything about the request, it needs a new one.

## Your connections and activity

![Your AI connections](../assets/ai/connect-your-ai-connections.png)

- Each AI client you connected, when you connected it, when you last used it
  and until when the connection lasts. After that you sign in again in your
  assistant.
- **Disconnect** ends all your connectors of that client at once (all your
  Claude connectors share one client). New sign-ins and token refreshes stop
  immediately; requests already signed in can keep working for up to 5
  minutes. To remove one connector only, use Claude's own Remove (or
  `claude mcp logout`).
- **Recent AI activity**: your last requests, as the tool names your AI used
  (`gitea__list_issues ✓`), with ⏸ *waiting for your confirmation* or ✗ and
  the reason when something was refused. Never the contents.

## Good to know

- What the AI reads in your apps is sent to the AI provider you use.
- You get exactly your own access: leave a group and the AI loses that app
  at your next request.
- On an [AI page](../operations/ai.md#the-ai-page) your administrator runs,
  "All my apps" is already the AI's only server: connect it once there and
  consent in the sign-in screen.
