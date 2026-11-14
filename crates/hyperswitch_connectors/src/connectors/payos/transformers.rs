use std::collections::{BTreeMap, HashMap};

use common_enums::enums;
use common_utils::{
    crypto::{self, SignMessage},
    errors::CustomResult,
    pii,
    request::Method,
    types::MinorUnit,
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, RealTimePaymentData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm},
    types::{PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsSyncRouterData},
};
use hyperswitch_interfaces::{
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    errors,
};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    types::{
        PaymentsCancelResponseRouterData, PaymentsResponseRouterData,
        PaymentsSyncResponseRouterData,
    },
    utils::{
        get_unimplemented_payment_method_error_message, is_payment_failure,
        PaymentsAuthorizeRequestData, RouterData as _,
    },
};

/// Maximum `orderCode` accepted by PayOS (`2^53 - 1`, JavaScript `Number.MAX_SAFE_INTEGER`).
pub const MAX_ORDER_CODE: u64 = (1u64 << 53) - 1;

/// Maximum payment description length accepted by PayOS for standard VietQR links.
pub const MAX_DESCRIPTION_LEN: usize = 25;

/// Default payment link expiry window (15 minutes) used when no request session expiry is provided.
pub const DEFAULT_PAYMENT_LINK_EXPIRY_SECS: i64 = 15 * 60;

pub const PAYOS_SUCCESS_CODE: &str = "00";

/// Derives a deterministic positive integer `orderCode` in `[1, 2^53 - 1]` from
/// `connector_request_reference_id`.
///
/// Collision reasoning:
/// - SHA-256 truncated to 53 bits produces a uniform space of `N = 2^53 - 1 ≈ 9.007 × 10^15` values
///   (mapping `0` to `1` adds negligible bias of `2^-53`).
/// - By the birthday bound, a 50% collision probability requires `~sqrt(2 * ln(2) * 2^53) ≈ 1.12 × 10^8`
///   distinct payment attempts on a single PayOS payment channel. For `10^6` orders on one channel,
///   the expected collision probability is `~(10^6)^2 / (2 * 2^53) ≈ 5.5 × 10^-5`.
/// - Determinism ensures retries of the same payment attempt produce the same `orderCode`, and
///   storing `orderCode` in `connector_response_reference_id` preserves an auditable mapping.
pub fn derive_order_code(connector_request_reference_id: &str) -> i64 {
    let digest = Sha256::digest(connector_request_reference_id.as_bytes());
    let mut first_eight = [0u8; 8];
    first_eight.copy_from_slice(&digest[..8]);
    let raw = u64::from_be_bytes(first_eight) & MAX_ORDER_CODE;
    let positive = if raw == 0 { 1 } else { raw };
    i64::try_from(positive).unwrap_or(1)
}

pub fn truncate_description(raw: Option<&str>, order_code: i64) -> String {
    let candidate = raw.map(str::trim).filter(|s| !s.is_empty());
    let base = match candidate {
        Some(text) => text.to_string(),
        None => format!("Pay {order_code}"),
    };
    base.chars().take(MAX_DESCRIPTION_LEN).collect()
}

pub fn create_payment_signature_payload(
    amount: i64,
    cancel_url: &str,
    description: &str,
    order_code: i64,
    return_url: &str,
) -> String {
    format!(
        "amount={amount}&cancelUrl={cancel_url}&description={description}&orderCode={order_code}&returnUrl={return_url}"
    )
}

pub fn compute_hmac_sha256_hex(
    checksum_key: &str,
    message: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let signature = crypto::HmacSha256
        .sign_message(checksum_key.as_bytes(), message.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(hex::encode(signature))
}

fn sort_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                if let Some(v) = map.get(k) {
                    sorted.insert(k.clone(), sort_json_value(v));
                }
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_value).collect())
        }
        other => other.clone(),
    }
}

/// Builds the PayOS canonical query string from a JSON object (`data` in webhooks):
/// keys sorted alphabetically, joined as `k1=v1&k2=v2...`, `null` mapped to empty string,
/// and arrays/objects JSON-stringified with nested object keys sorted.
pub fn build_sorted_query_string(
    data: &serde_json::Value,
) -> CustomResult<String, errors::ConnectorError> {
    let obj = data
        .as_object()
        .ok_or(errors::ConnectorError::WebhookBodyDecodingFailed)?;

    let sorted_entries: BTreeMap<&String, &serde_json::Value> = obj.iter().collect();
    let mut parts = Vec::with_capacity(sorted_entries.len());

    for (key, value) in sorted_entries {
        let formatted_value = match value {
            serde_json::Value::Null => String::new(),
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                serde_json::to_string(&sort_json_value(value))
                    .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?
            }
        };
        parts.push(format!("{key}={formatted_value}"));
    }

    Ok(parts.join("&"))
}

pub struct PayosRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for PayosRouterData<T> {
    fn from((amount, item): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayosAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) client_id: Secret<String>,
    pub(super) checksum_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PayosAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                client_id: key1.to_owned(),
                checksum_key: api_secret.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosItem {
    pub name: String,
    pub quantity: i32,
    pub price: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosPaymentsRequest {
    pub order_code: i64,
    pub amount: MinorUnit,
    pub description: String,
    pub cancel_url: String,
    pub return_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_email: Option<pii::Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<PayosItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<i64>,
    pub signature: Secret<String>,
}

impl TryFrom<&PayosRouterData<&PaymentsAuthorizeRouterData>> for PayosPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PayosRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        if item.router_data.request.currency != enums::Currency::VND {
            return Err(errors::ConnectorError::CurrencyNotSupported {
                message: item.router_data.request.currency.to_string(),
                connector: "payos",
            }
            .into());
        }

        let capture_method = item
            .router_data
            .request
            .capture_method
            .unwrap_or(enums::CaptureMethod::Automatic);
        if capture_method != enums::CaptureMethod::Automatic {
            return Err(errors::ConnectorError::CaptureMethodNotSupported.into());
        }

        match &item.router_data.request.payment_method_data {
            PaymentMethodData::RealTimePayment(rtp_data) => match **rtp_data {
                RealTimePaymentData::VietQr {} => {}
                RealTimePaymentData::DuitNow {}
                | RealTimePaymentData::Fps {}
                | RealTimePaymentData::PromptPay {}
                | RealTimePaymentData::Qris {} => {
                    return Err(errors::ConnectorError::NotImplemented(
                        get_unimplemented_payment_method_error_message("payos"),
                    )
                    .into());
                }
            },
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    get_unimplemented_payment_method_error_message("payos"),
                )
                .into());
            }
        }

        let amount_i64 = item.amount.get_amount_as_i64();
        if amount_i64 <= 0 {
            return Err(errors::ConnectorError::InvalidDataFormat {
                field_name: "amount".into(),
            }
            .into());
        }

        let auth = PayosAuthType::try_from(&item.router_data.connector_auth_type)?;
        let order_code = derive_order_code(&item.router_data.connector_request_reference_id);
        let description = truncate_description(item.router_data.description.as_deref(), order_code);
        let return_url = item.router_data.request.get_router_return_url()?;
        let cancel_url = return_url.clone();
        // PaymentsAuthorizeData in this schema does not carry session_expiry, so default to 15 min.
        let expired_at =
            Some(common_utils::date_time::now_unix_timestamp() + DEFAULT_PAYMENT_LINK_EXPIRY_SECS);

        let sign_payload = create_payment_signature_payload(
            amount_i64,
            &cancel_url,
            &description,
            order_code,
            &return_url,
        );
        let signature_hex = compute_hmac_sha256_hex(auth.checksum_key.peek(), &sign_payload)?;

        Ok(Self {
            order_code,
            amount: item.amount,
            description,
            cancel_url,
            return_url,
            buyer_name: item.router_data.get_optional_billing_full_name(),
            buyer_email: item.router_data.get_optional_billing_email(),
            buyer_phone: item.router_data.get_optional_billing_phone_number(),
            items: None,
            expired_at,
            signature: Secret::new(signature_hex),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosCancelRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_reason: Option<String>,
}

impl TryFrom<&PaymentsCancelRouterData> for PayosCancelRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PaymentsCancelRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            cancellation_reason: item.request.cancellation_reason.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PayosPaymentStatus {
    #[default]
    Pending,
    Processing,
    Paid,
    Underpaid,
    #[serde(alias = "CANCELED")]
    Cancelled,
    Expired,
    Failed,
}

impl PayosPaymentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Processing => "PROCESSING",
            Self::Paid => "PAID",
            Self::Underpaid => "UNDERPAID",
            Self::Cancelled => "CANCELLED",
            Self::Expired => "EXPIRED",
            Self::Failed => "FAILED",
        }
    }
}

impl From<PayosPaymentStatus> for enums::AttemptStatus {
    fn from(status: PayosPaymentStatus) -> Self {
        match status {
            PayosPaymentStatus::Paid => Self::Charged,
            PayosPaymentStatus::Pending | PayosPaymentStatus::Processing => {
                Self::AuthenticationPending
            }
            PayosPaymentStatus::Underpaid => Self::Pending,
            PayosPaymentStatus::Cancelled => Self::Voided,
            PayosPaymentStatus::Expired | PayosPaymentStatus::Failed => Self::Failure,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosApiResponse<T> {
    pub code: String,
    pub desc: String,
    pub data: Option<T>,
    pub signature: Option<Secret<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosCreatePaymentLinkData {
    pub bin: Option<String>,
    pub account_number: Option<String>,
    pub account_name: Option<String>,
    pub amount: MinorUnit,
    pub description: Option<String>,
    pub order_code: i64,
    pub currency: Option<String>,
    pub payment_link_id: String,
    pub status: PayosPaymentStatus,
    pub checkout_url: String,
    pub qr_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosPaymentLinkDetails {
    pub id: String,
    pub order_code: i64,
    pub amount: MinorUnit,
    pub amount_paid: Option<MinorUnit>,
    pub amount_remaining: Option<MinorUnit>,
    pub status: PayosPaymentStatus,
    pub created_at: Option<String>,
    pub transactions: Option<Vec<serde_json::Value>>,
    pub canceled_at: Option<String>,
    pub cancellation_reason: Option<String>,
}

fn build_api_error_response(
    code: String,
    desc: String,
    http_code: u16,
    attempt_status: Option<enums::AttemptStatus>,
    connector_transaction_id: Option<String>,
    connector_response_reference_id: Option<String>,
) -> ErrorResponse {
    ErrorResponse {
        code,
        message: desc.clone(),
        reason: Some(desc),
        status_code: http_code,
        attempt_status,
        connector_transaction_id,
        connector_response_reference_id,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
    }
}

impl TryFrom<PaymentsResponseRouterData<PayosApiResponse<PayosCreatePaymentLinkData>>>
    for PaymentsAuthorizeRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PaymentsResponseRouterData<PayosApiResponse<PayosCreatePaymentLinkData>>,
    ) -> Result<Self, Self::Error> {
        let http_code = item.http_code;
        if item.response.code != PAYOS_SUCCESS_CODE {
            let err = build_api_error_response(
                item.response.code,
                item.response.desc,
                http_code,
                Some(enums::AttemptStatus::Failure),
                None,
                None,
            );
            return Ok(Self {
                status: enums::AttemptStatus::Failure,
                response: Err(err),
                ..item.data
            });
        }

        let data = item
            .response
            .data
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;

        let status = enums::AttemptStatus::from(data.status);
        let connector_response_reference_id = Some(data.order_code.to_string());
        let redirection_data = RedirectForm::Form {
            endpoint: data.checkout_url,
            method: Method::Get,
            form_fields: HashMap::new(),
        };

        let response = if is_payment_failure(status) {
            Err(build_api_error_response(
                data.status.as_str().to_string(),
                format!("PayOS payment link status: {}", data.status.as_str()),
                http_code,
                Some(status),
                Some(data.payment_link_id),
                connector_response_reference_id,
            ))
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(data.payment_link_id),
                redirection_data: Box::new(Some(redirection_data)),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id,
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            })
        };

        Ok(Self {
            status,
            response,
            ..item.data
        })
    }
}

fn map_payment_link_details_response<F, Req>(
    api_response: PayosApiResponse<PayosPaymentLinkDetails>,
    data: RouterData<F, Req, PaymentsResponseData>,
    http_code: u16,
    error_attempt_status: Option<enums::AttemptStatus>,
) -> Result<RouterData<F, Req, PaymentsResponseData>, error_stack::Report<errors::ConnectorError>> {
    if api_response.code != PAYOS_SUCCESS_CODE {
        let err = build_api_error_response(
            api_response.code,
            api_response.desc,
            http_code,
            error_attempt_status,
            None,
            None,
        );
        return Ok(RouterData {
            status: error_attempt_status.unwrap_or(data.status),
            response: Err(err),
            ..data
        });
    }

    let details = api_response
        .data
        .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;
    let status = enums::AttemptStatus::from(details.status);
    let connector_response_reference_id = Some(details.order_code.to_string());

    let response = if is_payment_failure(status) {
        let reason = details
            .cancellation_reason
            .clone()
            .unwrap_or_else(|| format!("PayOS payment {}", details.status.as_str()));
        Err(build_api_error_response(
            details.status.as_str().to_string(),
            reason,
            http_code,
            Some(status),
            Some(details.id),
            connector_response_reference_id,
        ))
    } else {
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(details.id),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            network_txn_link_id: None,
            connector_response_reference_id,
            incremental_authorization_allowed: None,
            authentication_data: None,
            charges: None,
            payment_account_reference: None,
        })
    };

    Ok(RouterData {
        status,
        response,
        ..data
    })
}

impl TryFrom<PaymentsSyncResponseRouterData<PayosApiResponse<PayosPaymentLinkDetails>>>
    for PaymentsSyncRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PaymentsSyncResponseRouterData<PayosApiResponse<PayosPaymentLinkDetails>>,
    ) -> Result<Self, Self::Error> {
        map_payment_link_details_response(item.response, item.data, item.http_code, None)
    }
}

impl TryFrom<PaymentsCancelResponseRouterData<PayosApiResponse<PayosPaymentLinkDetails>>>
    for PaymentsCancelRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PaymentsCancelResponseRouterData<PayosApiResponse<PayosPaymentLinkDetails>>,
    ) -> Result<Self, Self::Error> {
        map_payment_link_details_response(
            item.response,
            item.data,
            item.http_code,
            Some(enums::AttemptStatus::VoidFailed),
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosWebhookBody {
    pub code: String,
    pub desc: String,
    pub success: Option<bool>,
    pub data: PayosWebhookData,
    pub signature: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosWebhookData {
    pub order_code: i64,
    pub amount: MinorUnit,
    pub description: Option<String>,
    pub account_number: Option<Secret<String>>,
    pub reference: Option<String>,
    pub transaction_date_time: Option<String>,
    pub currency: Option<String>,
    pub payment_link_id: String,
    pub code: String,
    pub desc: Option<String>,
    pub counter_account_bank_id: Option<String>,
    pub counter_account_bank_name: Option<String>,
    pub counter_account_name: Option<Secret<String>>,
    pub counter_account_number: Option<Secret<String>>,
    pub virtual_account_name: Option<Secret<String>>,
    pub virtual_account_number: Option<Secret<String>>,
}

impl From<PayosWebhookBody> for PayosApiResponse<PayosPaymentLinkDetails> {
    fn from(webhook: PayosWebhookBody) -> Self {
        let is_success = webhook.data.code == PAYOS_SUCCESS_CODE;
        let (status, amount_paid, amount_remaining, cancellation_reason) = if is_success {
            (
                PayosPaymentStatus::Paid,
                Some(webhook.data.amount),
                Some(MinorUnit::zero()),
                None,
            )
        } else {
            (
                PayosPaymentStatus::Failed,
                Some(MinorUnit::zero()),
                Some(webhook.data.amount),
                webhook.data.desc.clone(),
            )
        };

        Self {
            code: PAYOS_SUCCESS_CODE.to_string(),
            desc: "success".to_string(),
            data: Some(PayosPaymentLinkDetails {
                id: webhook.data.payment_link_id,
                order_code: webhook.data.order_code,
                amount: webhook.data.amount,
                amount_paid,
                amount_remaining,
                status,
                created_at: webhook.data.transaction_date_time,
                transactions: None,
                canceled_at: None,
                cancellation_reason,
            }),
            signature: Some(webhook.signature),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayosErrorResponse {
    pub code: Option<String>,
    pub desc: Option<String>,
}

impl PayosErrorResponse {
    pub fn into_error_response(self, status_code: u16) -> ErrorResponse {
        let message = self
            .desc
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string());
        ErrorResponse {
            status_code,
            code: self
                .code
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
            message,
            reason: self.desc,
            attempt_status: None,
            connector_transaction_id: None,
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use common_utils::crypto::{self, VerifySignature};
    use hyperswitch_domain_models::{
        payment_method_data::{PaymentMethodData, RealTimePaymentData},
        router_data::ConnectorAuthType,
        router_flow_types::payments::{Authorize, PSync, Void},
        router_request_types::{
            PaymentsAuthorizeData, PaymentsCancelData, PaymentsSyncData, SyncRequestType,
        },
        router_response_types::PaymentsResponseData,
    };
    use hyperswitch_masking::{ExposeInterface, Secret};

    use super::*;
    use crate::types::ResponseRouterData;

    fn sample_auth() -> ConnectorAuthType {
        ConnectorAuthType::SignatureKey {
            api_key: Secret::new("test-api-key".to_string()),
            key1: Secret::new("test-client-id".to_string()),
            api_secret: Secret::new("test_checksum_key_123".to_string()),
        }
    }

    fn sample_authorize_router_data(
        currency: enums::Currency,
        capture_method: Option<enums::CaptureMethod>,
        description: Option<&str>,
    ) -> PaymentsAuthorizeRouterData {
        let mut router_data = RouterData {
            flow: std::marker::PhantomData::<Authorize>,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "payos".to_string(),
            payment_id: "pay_test_123".to_string(),
            attempt_id: "att_test_123".to_string(),
            status: enums::AttemptStatus::Started,
            payment_method: enums::PaymentMethod::RealTimePayment,
            payment_method_type: Some(enums::PaymentMethodType::VietQr),
            connector_auth_type: sample_auth(),
            description: description.map(ToString::to_string),
            address: Default::default(),
            auth_type: enums::AuthenticationType::NoThreeDs,
            connector_meta_data: None,
            connector_wallets_details: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            recurring_mandate_payment_data: None,
            preprocessing_id: None,
            payment_method_status: None,
            connector_request_reference_id: "att_test_123".to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            test_mode: None,
            request: PaymentsAuthorizeData {
                payment_method_data: PaymentMethodData::RealTimePayment(Box::new(
                    RealTimePaymentData::VietQr {},
                )),
                amount: 50000,
                order_tax_amount: None,
                email: None,
                customer_name: None,
                currency,
                confirm: true,
                capture_method,
                router_return_url: Some("https://example.com/return".to_string()),
                webhook_url: None,
                complete_authorize_url: None,
                setup_future_usage: None,
                mandate_id: None,
                off_session: None,
                customer_acceptance: None,
                setup_mandate_details: None,
                browser_info: None,
                order_details: None,
                order_category: None,
                session_token: None,
                enrolled_for_3ds: false,
                related_transaction_id: None,
                payment_experience: None,
                payment_method_type: Some(enums::PaymentMethodType::VietQr),
                surcharge_details: None,
                customer_id: None,
                request_incremental_authorization: false,
                metadata: None,
                authentication_data: None,
                ucs_authentication_data: None,
                force_3ds_challenge: None,
                request_extended_authorization: None,
                split_payments: None,
                guest_customer: None,
                minor_amount: MinorUnit::new(50000),
                merchant_order_reference_id: None,
                integrity_object: None,
                shipping_cost: None,
                additional_payment_method_data: None,
                merchant_account_id: None,
                merchant_config_currency: None,
                connector_testing_data: None,
                order_id: None,
                locale: None,
                payment_channel: None,
                enable_partial_authorization: None,
                enable_overcapture: None,
                is_stored_credential: None,
                mit_category: None,
                billing_descriptor: None,
                tokenization: None,
                partner_merchant_identifier_details: None,
                feature_metadata: None,
                installment_details: None,
                connector_intent_metadata: None,
                is_account_funded_transaction: None,
                recipient_details: None,
                business_country: None,
                enable_avs_check: None,
            },
            response: Err(ErrorResponse::default()),
            connector_http_status_code: None,
            external_latency: None,
            connector_response: None,
            integrity_check: Ok(()),
            connector_api_version: None,
            frm_metadata: None,
            payment_method_balance: None,
            raw_connector_response: None,
            tenant_id: common_utils::id_type::TenantId::get_default_tenant_id(),
            apple_pay_flow: None,
            dispute_id: None,
            refund_id: None,
            payout_id: None,
            minor_amount_capturable: None,
            authorized_amount: None,
            accept_amount_mismatch: None,
            additional_merchant_data: None,
            header_payload: None,
            connector_mandate_request_reference_id: None,
            l2_l3_data: None,
            authentication_id: None,
            psd2_sca_exemption_type: None,
            is_payment_id_from_merchant: None,
            customer_document_details: None,
            customer_date_of_birth: None,
            feature_data: None,
            sender_payment_instrument_id: None,
            connector_returned_payment_method_details: None,
        };
        router_data.connector_request_reference_id = "att_test_123".to_string();
        router_data
    }

    #[test]
    fn test_create_payment_signature_known_vector() {
        let payload = create_payment_signature_payload(
            50000,
            "https://example.com/cancel",
            "Order 123",
            123456,
            "https://example.com/return",
        );
        assert_eq!(
            payload,
            "amount=50000&cancelUrl=https://example.com/cancel&description=Order 123&orderCode=123456&returnUrl=https://example.com/return"
        );
        let sig = compute_hmac_sha256_hex("test_checksum_key_123", &payload).unwrap();
        assert_eq!(
            sig,
            "fdbe1900fcca670fc25ffdd2525468ef4fd06760314365238a78f76f4caae53f"
        );
    }

    #[test]
    fn test_webhook_signature_sorted_keys_null_and_nested() {
        let data = serde_json::json!({
            "paymentLinkId": "124c33293c43417ab7879e14c8d9eb18",
            "orderCode": 123,
            "amount": 3000,
            "description": "VQRIO123",
            "code": "00",
            "counterAccountBankId": null,
            "counterAccountName": "",
            "items": [
                {
                    "quantity": 1,
                    "price": 3000,
                    "name": "Item A"
                }
            ]
        });

        let query_str = build_sorted_query_string(&data).unwrap();
        assert_eq!(
            query_str,
            r#"amount=3000&code=00&counterAccountBankId=&counterAccountName=&description=VQRIO123&items=[{"name":"Item A","price":3000,"quantity":1}]&orderCode=123&paymentLinkId=124c33293c43417ab7879e14c8d9eb18"#
        );

        let expected_sig =
            hex::decode("08f9001d8e1b9533f87990ef267581676bb7c2ac1892dc91b5341adfedabeb1a")
                .unwrap();
        let verified = crypto::HmacSha256
            .verify_signature(
                b"test_checksum_key_123",
                &expected_sig,
                query_str.as_bytes(),
            )
            .unwrap();
        assert!(verified);

        let wrong_verified = crypto::HmacSha256
            .verify_signature(b"wrong_key", &expected_sig, query_str.as_bytes())
            .unwrap();
        assert!(!wrong_verified);
    }

    #[test]
    fn test_status_mapping() {
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Paid),
            enums::AttemptStatus::Charged
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Pending),
            enums::AttemptStatus::AuthenticationPending
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Processing),
            enums::AttemptStatus::AuthenticationPending
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Underpaid),
            enums::AttemptStatus::Pending
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Cancelled),
            enums::AttemptStatus::Voided
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Expired),
            enums::AttemptStatus::Failure
        );
        assert_eq!(
            enums::AttemptStatus::from(PayosPaymentStatus::Failed),
            enums::AttemptStatus::Failure
        );
    }

    #[test]
    fn test_order_code_range_and_determinism() {
        let inputs = [
            "",
            "att_1",
            "pay_abc_1234567890",
            "merchant_order_with_a_very_long_identifier_string_999999999",
            "0",
        ];
        for input in inputs {
            let code1 = derive_order_code(input);
            let code2 = derive_order_code(input);
            assert_eq!(code1, code2);
            assert!(code1 >= 1, "orderCode must be positive for {input}");
            assert!(
                u64::try_from(code1).unwrap() <= MAX_ORDER_CODE,
                "orderCode must be <= 2^53 - 1 for {input}"
            );
        }
        assert_ne!(derive_order_code("att_1"), derive_order_code("att_2"));
    }

    #[test]
    fn test_authorize_request_validation_and_description_truncation() {
        let rd = sample_authorize_router_data(
            enums::Currency::VND,
            Some(enums::CaptureMethod::Automatic),
            Some("Thanh toan don hang rat dai vuot qua 25 ky tu"),
        );
        let req =
            PayosPaymentsRequest::try_from(&PayosRouterData::from((MinorUnit::new(50000), &rd)))
                .unwrap();
        assert_eq!(req.description.chars().count(), 25);
        assert_eq!(req.amount.get_amount_as_i64(), 50000);
        assert_eq!(req.return_url, "https://example.com/return");
        assert_eq!(req.cancel_url, "https://example.com/return");
        let now = common_utils::date_time::now_unix_timestamp();
        let expired_at = req.expired_at.expect("expiredAt must be populated");
        assert!(
            expired_at >= now + DEFAULT_PAYMENT_LINK_EXPIRY_SECS - 5
                && expired_at <= now + DEFAULT_PAYMENT_LINK_EXPIRY_SECS + 5,
            "expiredAt {expired_at} not near now + {DEFAULT_PAYMENT_LINK_EXPIRY_SECS}"
        );
        assert!(!req.signature.expose().is_empty());

        let usd_rd = sample_authorize_router_data(
            enums::Currency::USD,
            Some(enums::CaptureMethod::Automatic),
            None,
        );
        let usd_err = PayosPaymentsRequest::try_from(&PayosRouterData::from((
            MinorUnit::new(50000),
            &usd_rd,
        )))
        .unwrap_err();
        assert!(matches!(
            usd_err.current_context(),
            errors::ConnectorError::CurrencyNotSupported { .. }
        ));

        let manual_rd = sample_authorize_router_data(
            enums::Currency::VND,
            Some(enums::CaptureMethod::Manual),
            None,
        );
        let manual_err = PayosPaymentsRequest::try_from(&PayosRouterData::from((
            MinorUnit::new(50000),
            &manual_rd,
        )))
        .unwrap_err();
        assert!(matches!(
            manual_err.current_context(),
            errors::ConnectorError::CaptureMethodNotSupported
        ));
    }

    #[test]
    fn test_create_response_success_and_error_code() {
        let rd = sample_authorize_router_data(
            enums::Currency::VND,
            Some(enums::CaptureMethod::Automatic),
            Some("Order 1"),
        );
        let ok_resp: PayosApiResponse<PayosCreatePaymentLinkData> = serde_json::from_str(
            r#"{
                "code": "00",
                "desc": "success",
                "data": {
                    "bin": "970422",
                    "accountNumber": "123456",
                    "accountName": "TEST",
                    "amount": 50000,
                    "description": "Order 1",
                    "orderCode": 123456,
                    "currency": "VND",
                    "paymentLinkId": "plink_abc",
                    "status": "PENDING",
                    "checkoutUrl": "https://pay.payos.vn/web/plink_abc",
                    "qrCode": "00020101..."
                },
                "signature": "sig"
            }"#,
        )
        .unwrap();

        let out = PaymentsAuthorizeRouterData::try_from(ResponseRouterData {
            response: ok_resp,
            data: rd.clone(),
            http_code: 200,
        })
        .unwrap();
        assert_eq!(out.status, enums::AttemptStatus::AuthenticationPending);
        match out.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                connector_response_reference_id,
                ..
            } => {
                assert!(matches!(
                    resource_id,
                    ResponseId::ConnectorTransactionId(ref id) if id == "plink_abc"
                ));
                assert_eq!(connector_response_reference_id, Some("123456".to_string()));
                assert!(matches!(
                    *redirection_data,
                    Some(RedirectForm::Form { ref endpoint, method: Method::Get, .. })
                        if endpoint == "https://pay.payos.vn/web/plink_abc"
                ));
            }
            other => panic!("unexpected response variant: {other:?}"),
        }

        let err_resp: PayosApiResponse<PayosCreatePaymentLinkData> =
            serde_json::from_str(r#"{"code": "231", "desc": "Don hang da ton tai", "data": null}"#)
                .unwrap();
        let err_out = PaymentsAuthorizeRouterData::try_from(ResponseRouterData {
            response: err_resp,
            data: rd,
            http_code: 200,
        })
        .unwrap();
        assert_eq!(err_out.status, enums::AttemptStatus::Failure);
        let err = err_out.response.unwrap_err();
        assert_eq!(err.code, "231");
        assert_eq!(err.message, "Don hang da ton tai");
    }

    fn sample_psync_router_data(current_status: enums::AttemptStatus) -> PaymentsSyncRouterData {
        RouterData {
            flow: std::marker::PhantomData::<PSync>,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "payos".to_string(),
            payment_id: "pay_test_123".to_string(),
            attempt_id: "att_test_123".to_string(),
            status: current_status,
            payment_method: enums::PaymentMethod::RealTimePayment,
            payment_method_type: Some(enums::PaymentMethodType::VietQr),
            connector_auth_type: sample_auth(),
            description: None,
            address: Default::default(),
            auth_type: enums::AuthenticationType::NoThreeDs,
            connector_meta_data: None,
            connector_wallets_details: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            recurring_mandate_payment_data: None,
            preprocessing_id: None,
            payment_method_status: None,
            connector_request_reference_id: "att_test_123".to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            test_mode: None,
            request: PaymentsSyncData {
                connector_transaction_id: ResponseId::ConnectorTransactionId(
                    "plink_webhook_1".to_string(),
                ),
                sync_type: SyncRequestType::SinglePaymentSync,
                amount: MinorUnit::new(50000),
                currency: enums::Currency::VND,
                ..Default::default()
            },
            response: Err(ErrorResponse::default()),
            connector_http_status_code: None,
            external_latency: None,
            connector_response: None,
            integrity_check: Ok(()),
            connector_api_version: None,
            frm_metadata: None,
            payment_method_balance: None,
            raw_connector_response: None,
            tenant_id: common_utils::id_type::TenantId::get_default_tenant_id(),
            apple_pay_flow: None,
            dispute_id: None,
            refund_id: None,
            payout_id: None,
            minor_amount_capturable: None,
            authorized_amount: None,
            accept_amount_mismatch: None,
            additional_merchant_data: None,
            header_payload: None,
            connector_mandate_request_reference_id: None,
            l2_l3_data: None,
            authentication_id: None,
            psd2_sca_exemption_type: None,
            is_payment_id_from_merchant: None,
            customer_document_details: None,
            customer_date_of_birth: None,
            feature_data: None,
            sender_payment_instrument_id: None,
            connector_returned_payment_method_details: None,
        }
    }

    fn sample_void_router_data(current_status: enums::AttemptStatus) -> PaymentsCancelRouterData {
        RouterData {
            flow: std::marker::PhantomData::<Void>,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "payos".to_string(),
            payment_id: "pay_test_123".to_string(),
            attempt_id: "att_test_123".to_string(),
            status: current_status,
            payment_method: enums::PaymentMethod::RealTimePayment,
            payment_method_type: Some(enums::PaymentMethodType::VietQr),
            connector_auth_type: sample_auth(),
            description: None,
            address: Default::default(),
            auth_type: enums::AuthenticationType::NoThreeDs,
            connector_meta_data: None,
            connector_wallets_details: None,
            amount_captured: None,
            minor_amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            recurring_mandate_payment_data: None,
            preprocessing_id: None,
            payment_method_status: None,
            connector_request_reference_id: "att_test_123".to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            test_mode: None,
            request: PaymentsCancelData {
                connector_transaction_id: "plink_webhook_1".to_string(),
                cancellation_reason: Some("Customer requested cancel".to_string()),
                ..Default::default()
            },
            response: Err(ErrorResponse::default()),
            connector_http_status_code: None,
            external_latency: None,
            connector_response: None,
            integrity_check: Ok(()),
            connector_api_version: None,
            frm_metadata: None,
            payment_method_balance: None,
            raw_connector_response: None,
            tenant_id: common_utils::id_type::TenantId::get_default_tenant_id(),
            apple_pay_flow: None,
            dispute_id: None,
            refund_id: None,
            payout_id: None,
            minor_amount_capturable: None,
            authorized_amount: None,
            accept_amount_mismatch: None,
            additional_merchant_data: None,
            header_payload: None,
            connector_mandate_request_reference_id: None,
            l2_l3_data: None,
            authentication_id: None,
            psd2_sca_exemption_type: None,
            is_payment_id_from_merchant: None,
            customer_document_details: None,
            customer_date_of_birth: None,
            feature_data: None,
            sender_payment_instrument_id: None,
            connector_returned_payment_method_details: None,
        }
    }

    #[test]
    fn test_webhook_resource_roundtrip_to_psync_charged() {
        let webhook_json = r#"{
            "code": "00",
            "desc": "success",
            "success": true,
            "data": {
                "orderCode": 987654,
                "amount": 50000,
                "description": "Order 1",
                "accountNumber": "123456",
                "reference": "FT25001",
                "transactionDateTime": "2025-01-01 12:00:00",
                "currency": "VND",
                "paymentLinkId": "plink_webhook_1",
                "code": "00",
                "desc": "success"
            },
            "signature": "abcdef01"
        }"#;

        let webhook_body: PayosWebhookBody = serde_json::from_str(webhook_json).unwrap();
        let resource_obj = PayosApiResponse::<PayosPaymentLinkDetails>::from(webhook_body);
        let serialized_bytes = serde_json::to_vec(&resource_obj).unwrap();
        let parsed_psync: PayosApiResponse<PayosPaymentLinkDetails> =
            serde_json::from_slice(&serialized_bytes).unwrap();

        let psync_rd = sample_psync_router_data(enums::AttemptStatus::AuthenticationPending);
        let out = PaymentsSyncRouterData::try_from(ResponseRouterData {
            response: parsed_psync,
            data: psync_rd,
            http_code: 200,
        })
        .unwrap();

        assert_eq!(out.status, enums::AttemptStatus::Charged);
        match out.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                connector_response_reference_id,
                ..
            } => {
                assert!(matches!(
                    resource_id,
                    ResponseId::ConnectorTransactionId(ref id) if id == "plink_webhook_1"
                ));
                assert_eq!(connector_response_reference_id, Some("987654".to_string()));
            }
            other => panic!("unexpected response variant: {other:?}"),
        }
    }

    #[test]
    fn test_psync_and_void_non_success_code_status_handling() {
        let err_payload = r#"{"code": "101", "desc": "Payment link not found", "data": null}"#;
        let psync_resp: PayosApiResponse<PayosPaymentLinkDetails> =
            serde_json::from_str(err_payload).unwrap();
        let psync_rd = sample_psync_router_data(enums::AttemptStatus::AuthenticationPending);
        let psync_out = PaymentsSyncRouterData::try_from(ResponseRouterData {
            response: psync_resp,
            data: psync_rd,
            http_code: 200,
        })
        .unwrap();
        assert_eq!(
            psync_out.status,
            enums::AttemptStatus::AuthenticationPending
        );
        let psync_err = psync_out.response.unwrap_err();
        assert_eq!(psync_err.attempt_status, None);
        assert_eq!(psync_err.code, "101");

        let void_resp: PayosApiResponse<PayosPaymentLinkDetails> =
            serde_json::from_str(err_payload).unwrap();
        let void_rd = sample_void_router_data(enums::AttemptStatus::AuthenticationPending);
        let void_out = PaymentsCancelRouterData::try_from(ResponseRouterData {
            response: void_resp,
            data: void_rd,
            http_code: 200,
        })
        .unwrap();
        assert_eq!(void_out.status, enums::AttemptStatus::VoidFailed);
        let void_err = void_out.response.unwrap_err();
        assert_eq!(
            void_err.attempt_status,
            Some(enums::AttemptStatus::VoidFailed)
        );
        assert_eq!(void_err.code, "101");
    }
}
