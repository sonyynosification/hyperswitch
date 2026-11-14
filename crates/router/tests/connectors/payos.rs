use hyperswitch_domain_models::payment_method_data::{PaymentMethodData, RealTimePaymentData};
use router::types::{self, api, storage::enums};

use crate::{
    connector_auth,
    utils::{self, ConnectorActions},
};

#[derive(Clone, Copy)]
struct PayosTest;
impl ConnectorActions for PayosTest {}
impl utils::Connector for PayosTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Payos;
        utils::construct_connector_data_old(
            Box::new(Payos::new()),
            types::Connector::Payos,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .payos
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "payos".to_string()
    }
}

static CONNECTOR: PayosTest = PayosTest {};

fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    None
}

fn payment_method_details() -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        amount: 50000,
        currency: enums::Currency::VND,
        payment_method_data: PaymentMethodData::RealTimePayment(Box::new(
            RealTimePaymentData::VietQr {},
        )),
        confirm: true,
        capture_method: Some(enums::CaptureMethod::Automatic),
        payment_method_type: Some(enums::PaymentMethodType::VietQr),
        router_return_url: Some("https://example.com/return".to_string()),
        ..Default::default()
    })
}

#[actix_web::test]
#[ignore = "Requires live PayOS credentials"]
async fn should_create_vietqr_payment_link() {
    let response = CONNECTOR
        .authorize_payment(payment_method_details(), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
}
