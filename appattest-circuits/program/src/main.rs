//! A simple program to be proven inside the zkVM.
// sp1_zkvm::entrypoint!(main);
mod decode;
use decode::decode_attestation;
use decode::decode_assertion;

mod assertion;
use assertion::validate_assertion;

pub fn main() {
    
    // let raw_attestation = sp1_zkvm::io::read::<String>();
    // let raw_assertion = sp1_zkvm::io::read::<String>();
    // let challenge = sp1_zkvm::io::read::<Vec<u8>>(); 
    // let bundle_id = sp1_zkvm::io::read::<String>();
    
    // // Decode base64 strings into attestation and assertion objects.
    // let attestation = decode_attestation(raw_attestation);
    // let assertion = decode_assertion(raw_assertion);

    // // Verify attestation and assertion.
    // let is_valid_attestation = validate_attestation(attestation, challenge);
    // // TODO: get the public key from the attestation
    // // let is_valid_assertion = validate_assertion(assertion, challenge, public_key_bytes);

    // sp1_zkvm::io::commit(&is_valid_attestation);
    // sp1_zkvm::io::commit(&is_valid_assertion);

    let encoded = "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXagcCErMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAxMjI1MTkwNDMxWhcNMjAxMjI4MTkwNDMxWjCBkTFJMEcGA1UEAwxANGJiNjY4ZjRkNTZlOTZmZjQwNTc0MThhOWFmZTNlNjJmNDlhOWEyNDUyOGMwNTU4ZTkxZDA2MGQ3NDJlMDQ2ZTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6JwnVMcs0V09NqnYLYqAQKGQLSFPjHShTIsuC0qBEOhfiABl9IGSwjn--Zez0StflHcn8KgxgWDBI8uU7OZlJo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIFzbnZBzQEVbY3PmdStz_DaEU2AiFfrqu3wWXwutrAfMMAoGCCqGSM49BAMCA2gAMGUCMQCRuW8mwdBiWX50NpAbT_ArXRqu_R4U1nw1qoB9-fcBKG37bLJLSzUHH3eaDn9VpgMCMCluiKlZhwcRCMkIhpeowhZZimKJWwn6XWPSYakvstRyDH935BtMCASob93RiUpOTFkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmMx1DPn13vHz03OyEHQFPMYaJ0ZmXg850aiannHVUXFDRQAAAAAAAAAAAAAAAAAAAAAAAAAAABRhlWZMDpPGg2CWmkLF-yJIcdbNtKUBAgMmIAEhWCB6JwnVMcs0V09NqnYLYqAQKGQLSFPjHShTIsuC0qBEOiJYIBfiABl9IGSwjn--Zez0StflHcn8KgxgWDBI8uU7OZlJ";
    let attestation_result = decode_attestation(encoded);
    println!("DECODED ATTESTATION:\n{:?}", attestation_result); 

    println!("");

    // Test assertion object.
    let public_key_uncompressed_hex = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082";
    let encoded_assertion = "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD";
    let client_data = "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9";
    
    let assertion = decode_assertion(encoded_assertion);
    println!("DECODED ASSERTION:\n{:?}", assertion);
    let res = validate_assertion(assertion.unwrap(), client_data.to_string(), public_key_uncompressed_hex.to_string());
    println!("{}", res);
}





