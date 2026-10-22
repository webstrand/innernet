# Problem types of the TLS API

The API of TLS sessions answers every error with a problem detail (RFC 9457), encoded in CBOR in
its core deterministic encoding (RFC 8949, section 4.2.1), with the content type
`application/problem+cbor`. A problem is a map with the string keys of RFC 9457: `type`,
`title`, `status`, `detail` and `instance`, and the extension members of its type. Members that a
problem lacks are left out, and members that a client does not know are ignored. A problem
without a `type` has the type `about:blank`. Problems carry no version: a client should list
`application/problem+cbor` in `Accept` beside the versions of the API that it reads. A request
whose `Accept` chooses the debug view, a missing `Accept` or one that names no version that the
server writes but accepts `*/*` or `application/*`, gets its problems in the debug view too: in
CBOR diagnostic notation, with the content type `application/problem+cbor-diagnostic`, after the
same comment line as the debug view of a body.

A client decides on `type` alone. `status` is advisory: it repeats the status of the response, so
that a problem keeps its meaning over a transport other than HTTP. An error without a meaning of
innernet's own, such as a malformed body, a missing route or an internal error, has the type
`about:blank`; its `title` is the reason phrase of its status, which carries the meaning. A 404
of type `about:blank` names a route that the server does not have, never a peer, CIDR or
association that it does not hold.

The API of plain-HTTP sessions, which clients that predate TLS use, answers errors as before:
with an explanation in plain text for the errors that such clients cannot make sense of on their
own, and with an empty body otherwise.

The types below are innernet's own. Each URI is a random (version 4) UUID, fixed once, which
never changes. The constants in `shared/src/problem.rs` hold the same URIs.

| Type | Title | Status | Meaning |
| --- | --- | --- | --- |
| `urn:uuid:89b644bc-0770-472b-a3bc-09d1b32671ab` | The peer must connect over TLS | 401 | The peer has connected over TLS before, and so may no longer use plain HTTP. Only a plain-HTTP session meets this problem, which it is told in text. |
| `urn:uuid:1ca511f1-e703-4be8-b81e-c2a4e3491971` | Only a peer that has connected over TLS can be made an admin | 422 | The admin tried to promote a peer that has never connected over TLS. The peer must first run `innernet fetch` with a version of innernet that speaks TLS. |
| `urn:uuid:6b53f45a-cd2d-4f6b-9d24-676d699d3186` | The peer has changed since it was read | 409 | The tag of the change is stale. The admin client must read the peer again before it changes the peer. |
| `urn:uuid:94053d8e-85af-4eff-9cc3-ac9feb41dc58` | The CIDR has changed since it was read | 409 | The tag of the change is stale. The admin client must read the CIDR again before it changes the CIDR. |
| `urn:uuid:97c8ab2c-72e8-4c22-8329-8328530f14c6` | The change carries no tag | 400 | A `PUT` or `DELETE` of a tagged resource, a peer, its endpoints, its delegations or a CIDR, carries no tag. |
| `urn:uuid:231e8a92-c48e-4982-855e-3998840439fb` | No peer has this public key | 404 | No peer has the public key that the path names: the invitation expired, or was redeemed under a new key. |
| `urn:uuid:e97fda0b-cfc5-4c54-8761-442df29a96bc` | No CIDR has this prefix | 404 | No CIDR has the prefix that the path names. |
| `urn:uuid:03638e35-e88a-463b-87cf-8ee3fd4e5e69` | No association joins these CIDRs | 404 | No association joins the CIDRs that the path names, in either order. |
| `urn:uuid:08ea2dd5-0cbf-4efc-b0ef-d154acd09982` | The delegations break the rules of delegations | 422 | The delegations lie outside every CIDR, in several CIDRs or in a CIDR with children, hold the network or broadcast address of their CIDR, overlap each other or one of another peer, or take away the delegation of the server's internal address. `detail` explains which rule. A delegation that overlaps one of another peer is named in the extension members `prefix`, the refused delegation, `held`, the delegation of the other peer, and `holder`, the public key of the other peer. |

The extension members `prefix` and `held` are prefixes as the TLS API answers them, as text in
the form `address/length`. `holder` is the public key, as text in base64.
