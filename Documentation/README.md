# bgpls documentation

Start with the [Terminal-first lab quickstart](../lab-examples/bgpls/README.md)
to see a complete topology. The library and CLI can also connect to an
independently configured BGP-LS producer.

| Guide | Purpose |
| --- | --- |
| [Library usage](LibraryUsage.md) | Explicit configuration, a complete Swift example, callbacks, snapshots, and watch contracts |
| [Architecture](Architecture.md) | Modules, pipeline ownership, identity, buffering, and shutdown |
| [Protocol support](ProtocolSupport.md) | Supported encodings, typed attributes, recovery rules, and limits |
| [Lab guide](Lab/README.md) | Prerequisites, topology, script recipes, and optional tooling |
| [One-time OrbStack setup](Lab/OrbStackSetup.md) | Prepare the Linux host from macOS Terminal before deploying a lab |
| [FRR quickstart](../lab-examples/bgpls/README.md) | Authoritative build, deploy, collect, flap, and destroy workflow |
| [cEOS extension](../lab-examples/bgpls/CEOS.md) | An entitled second vendor image and independent collectors |
| [Qualification summary](../lab-examples/bgpls/VALIDATION.md) | Historical evidence and current release-preparation checks |
| [Draft 0.1.0 notes](ReleaseNotes/0.1.0.md) | Candidate scope and remaining publication gates |

The reference lab is a demonstration and interoperability test environment.
Production applications can depend on the released library while supplying
their own supervision, durable storage, observability, and access controls.
