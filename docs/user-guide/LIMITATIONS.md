# Limitations

CanaryCI grades recorded behavior against explicit assertions and planted values. A passing run establishes that the evaluated trial stayed within those assertions. The packaged fixtures use simulated enterprise tools. Production authorization, tenant scope, and network behavior require separate tests with your own controls and tool schemas.

`--trials` measures variance for the sampled model, settings, and prompts. `secure^k` and `breach@k` estimate outcomes under independent encounters at the observed rate. Sampling variation and model changes still matter. The offline benchmark reports fixture outcomes and uses no live model.

Use CanaryCI alongside runtime authorization, least privilege, egress controls, and a production sandbox. Configure external adapters and policies only for endpoints you control. The local browser reference adapter reads fixture pages with JavaScript disabled. The offline scenarios exercise DOM actions through simulated tool calls.

Encrypted or novel encodings can evade a detector that only sees selected trace fields. Add a tripwire for prohibited actions independently of how data is represented. Audit digests protect the recorded files. Supply a trusted public key to verify signer identity.
