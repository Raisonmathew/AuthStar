use anyhow::Result;
use grpc_api::eiaa::runtime::{
    capsule_runtime_client::CapsuleRuntimeClient, CapsuleSigned, ExecuteRequest,
    ExecuteResponse, GetPublicKeysRequest, AuthEvidence,
};
use tonic::transport::Channel;

#[derive(Clone)]
pub struct EiaaRuntimeClient {
    client: CapsuleRuntimeClient<Channel>,
}

impl EiaaRuntimeClient {
    pub async fn connect(addr: String) -> Result<Self> {
        let client = CapsuleRuntimeClient::connect(addr).await?;
        Ok(Self { client })
    }

    pub async fn execute_capsule(
        &mut self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
    ) -> Result<ExecuteResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let req = ExecuteRequest {
            capsule: Some(capsule),
            input_json,
            nonce_b64,
            now_unix: now,
            expires_at_unix: now + 300, // 5 minutes
            auth_evidence: None,
        };

        let response = self.client.execute(req).await?;
        Ok(response.into_inner())
    }

    /// Execute capsule with authentication evidence from an IdP assertion.
    /// Used for SSO login flows where the capsule needs IdP context to make decisions.
    pub async fn execute_with_evidence(
        &mut self,
        capsule: CapsuleSigned,
        input_json: String,
        nonce_b64: String,
        evidence: AuthEvidence,
    ) -> Result<ExecuteResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let req = ExecuteRequest {
            capsule: Some(capsule),
            input_json,
            nonce_b64,
            now_unix: now,
            expires_at_unix: now + 300,
            auth_evidence: Some(evidence),
        };

        let response = self.client.execute(req).await?;
        Ok(response.into_inner())
    }

    /// Fetch public keys from the runtime for attestation verification.
    /// Returns a list of (kid, pk_b64) tuples.
    pub async fn get_public_keys(&mut self) -> Result<Vec<(String, String)>> {
        let response = self.client.get_public_keys(GetPublicKeysRequest {}).await?;
        let keys = response
            .into_inner()
            .keys
            .into_iter()
            .map(|k| (k.kid, k.pk_b64))
            .collect();
        Ok(keys)
    }
}
