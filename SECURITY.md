# Security Policy

Do not include customer documents, environment values, purge tokens, AWS credentials, Cognito tokens, or object contents in an issue. Report suspected vulnerabilities privately to the repository owner with the affected function, reproducible conditions, and observed impact.

The implementation is a reference architecture. Before production use, perform threat modeling for the deployed region and data class, replace the HMAC secret with a Secrets Manager or KMS-backed signing design, authenticate the inference endpoint, configure an on-call subscription, test restore procedures, and verify effective permissions with the organization's SCPs and boundaries included.

