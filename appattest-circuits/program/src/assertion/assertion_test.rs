use assertion::assertion;

pub fn main() {
    let public_key_bytes = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082".as_bytes();
    let raw_assertion = "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD";
    let challenge = "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9";
    
    let assertion = assertion::decode_assertion(raw_assertion);
    println!("decoded assertion:{:?}", assertion);
    let res = assertion::validate_assertion(assertion, challenge, public_key_bytes);
    println!("{}", res);
}