#![cfg(all(feature = "alloc", any(feature = "ring", feature = "aws-lc-rs")))]

use core::time::Duration;
use std::error::Error as StdError;

use pki_types::{CertificateDer, UnixTime};
use rcgen::ExtendedKeyUsagePurpose;
use webpki::{ExtendedKeyUsage, RequiredEkuNotFoundContext, anchor_from_trusted_cert};

mod common;

fn check_cert(
    ee: &[u8],
    ca: &[u8],
    eku: &ExtendedKeyUsage,
    time: UnixTime,
    result: Result<(), webpki::Error>,
) {
    let ca = CertificateDer::from(ca);
    let anchors = [anchor_from_trusted_cert(&ca).unwrap()];

    let ee = CertificateDer::from(ee);
    let cert = webpki::EndEntityCert::try_from(&ee).unwrap();

    assert_eq!(
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            time,
            eku,
            None,
            None,
        )
        .map(|_| ()),
        result
    );
}

fn code_signing_cert() -> Result<(rcgen::Certificate, CertificateDer<'static>), Box<dyn StdError>> {
    let issuer = common::make_issuer("Code Signing CA")?;
    let end_entity = common::make_end_entity(
        vec![ExtendedKeyUsagePurpose::CodeSigning],
        "Code Signing EE",
        &issuer,
    )?;
    Ok((end_entity.cert, issuer.as_ref().der().clone()))
}

#[test]
pub fn verify_custom_eku_mdoc() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_609_459_200)); //  Jan 1 01:00:00 CET 2021

    let ee = include_bytes!("misc/mdoc_eku.ee.der");
    let ca = include_bytes!("misc/mdoc_eku.ca.der");

    let eku_mdoc = ExtendedKeyUsage::required(&[40, 129, 140, 93, 5, 1, 2]);
    check_cert(ee, ca, &eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        &ExtendedKeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: ExtendedKeyUsage::server_auth(),
                present: vec![vec![1, 0, 18013, 5, 1, 2]],
            },
        )),
    );
    check_cert(ee, ca, &eku_mdoc, time, Ok(()));
    check_cert(
        ee,
        ca,
        &ExtendedKeyUsage::server_auth(),
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: ExtendedKeyUsage::server_auth(),
                present: vec![vec![1, 0, 18013, 5, 1, 2]],
            },
        )),
    );
}

#[test]
pub fn verify_custom_eku_client() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &ExtendedKeyUsage::client_auth(), time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &ExtendedKeyUsage::client_auth(), time, Ok(()));
    check_cert(ee, ca, &ExtendedKeyUsage::server_auth(), time, Ok(()));
}

#[test]
pub fn verify_custom_eku_required_if_present() {
    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));

    let eku = ExtendedKeyUsage::required_if_present(&[43, 6, 1, 5, 5, 7, 3, 2]);

    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &eku, time, Ok(()));

    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(ee, ca, &eku, time, Ok(()));
}

#[test]
pub fn verify_code_signing_eku() {
    // Verify CODE_SIGNING_REPR constant is correct
    assert_eq!(
        ExtendedKeyUsage::CODE_SIGNING_REPR,
        &[1, 3, 6, 1, 5, 5, 7, 3, 3]
    );

    let time = UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d));
    let eku = ExtendedKeyUsage::code_signing();

    // Certificate that explicitly carries the codeSigning EKU is accepted
    let (code_signing_ee, code_signing_ca) = code_signing_cert().unwrap();
    check_cert(
        code_signing_ee.der(),
        code_signing_ca.as_ref(),
        &eku,
        time,
        Ok(()),
    );

    // Verify code_signing() method returns correct OID values
    let oid_values: Vec<usize> = eku.oid_values().collect();
    assert_eq!(oid_values, vec![1, 3, 6, 1, 5, 5, 7, 3, 3]);

    // Verify that a certificate without EKU is rejected for code signing
    let ee = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_no_eku_accepted_for_client_auth.ca.der");
    check_cert(
        ee,
        ca,
        &eku,
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: eku,
                present: vec![],
            },
        )),
    );

    // Verify that a certificate with server/client EKU is rejected for code signing
    let ee = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ee.der");
    let ca = include_bytes!("custom_ekus/cert_with_both_ekus_accepted_for_client_auth.ca.der");
    check_cert(
        ee,
        ca,
        &eku,
        time,
        Err(webpki::Error::RequiredEkuNotFound(
            RequiredEkuNotFoundContext {
                required: eku,
                present: vec![
                    vec![1, 3, 6, 1, 5, 5, 7, 3, 2], // clientAuth
                    vec![1, 3, 6, 1, 5, 5, 7, 3, 1], // serverAuth
                ],
            },
        )),
    );
}
