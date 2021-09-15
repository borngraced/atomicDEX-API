use crate::mm2::lp_bot::{SimpleCoinMarketMakerCfg, SimpleMakerBotRegistry, TickerInfosRegistry, TradingBotContext,
                         TradingBotState};
use crate::mm2::lp_ordermatch::{retrieve_my_maker_orders, MakerOrder};
use common::{executor::{spawn, Timer},
             log::{error, info},
             mm_ctx::MmArc,
             mm_error::MmError,
             slurp_url, HttpStatusCode};
use derive_more::Display;
use http::{HeaderMap, StatusCode};
use serde_json::Value as Json;
use std::collections::HashSet;
use std::str::Utf8Error;
use uuid::Uuid;

// !< constants
const KMD_PRICE_ENDPOINT: &str = "https://prices.komodo.live:1313/api/v1/tickers";

// !< Type definitions
pub type StartSimpleMakerBotResult = Result<StartSimpleMakerBotRes, MmError<StartSimpleMakerBotError>>;
pub type StopSimpleMakerBotResult = Result<StopSimpleMakerBotRes, MmError<StopSimpleMakerBotError>>;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct StartSimpleMakerBotRequest {
    cfg: SimpleMakerBotRegistry,
}

#[cfg(test)]
impl StartSimpleMakerBotRequest {
    pub fn new() -> StartSimpleMakerBotRequest {
        return StartSimpleMakerBotRequest {
            cfg: Default::default(),
        };
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StopSimpleMakerBotRes {
    result: String,
}

#[cfg(test)]
impl StopSimpleMakerBotRes {
    pub fn get_result(&self) -> String { self.result.clone() }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StartSimpleMakerBotRes {
    result: String,
}

#[cfg(test)]
impl StartSimpleMakerBotRes {
    pub fn get_result(&self) -> String { self.result.clone() }
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum StopSimpleMakerBotError {
    #[display(fmt = "The bot is already stopped")]
    AlreadyStopped,
    #[display(fmt = "The bot is already stopping")]
    AlreadyStopping,
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum StartSimpleMakerBotError {
    #[display(fmt = "The bot is already started")]
    AlreadyStarted,
    #[display(fmt = "Invalid bot configuration")]
    InvalidBotConfiguration,
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

#[derive(Debug)]
pub enum PriceServiceRequestError {
    HttpProcessError(String),
}

impl From<std::string::String> for PriceServiceRequestError {
    fn from(error: String) -> Self { PriceServiceRequestError::HttpProcessError(error) }
}

impl From<std::str::Utf8Error> for PriceServiceRequestError {
    fn from(error: Utf8Error) -> Self { PriceServiceRequestError::HttpProcessError(error.to_string()) }
}

impl HttpStatusCode for StartSimpleMakerBotError {
    fn status_code(&self) -> StatusCode {
        match self {
            StartSimpleMakerBotError::AlreadyStarted | StartSimpleMakerBotError::InvalidBotConfiguration => {
                StatusCode::BAD_REQUEST
            },
            StartSimpleMakerBotError::Transport(_) | StartSimpleMakerBotError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

impl HttpStatusCode for StopSimpleMakerBotError {
    fn status_code(&self) -> StatusCode {
        match self {
            // maybe bad request is not adapted for the first errors.
            StopSimpleMakerBotError::AlreadyStopped | StopSimpleMakerBotError::AlreadyStopping => {
                StatusCode::BAD_REQUEST
            },
            StopSimpleMakerBotError::Transport(_) | StopSimpleMakerBotError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

struct TradingPair {
    base: String,
    rel: String,
}

impl TradingPair {
    pub fn new(base: String, rel: String) -> TradingPair { TradingPair { base, rel } }

    pub fn as_combination(&self) -> String { self.base.clone() + "/" + self.rel.clone().as_str() }
}

pub async fn tear_down_bot(ctx: MmArc) {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut trading_bot_cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await;
        // todo: check if clear is adapted, if i understand its keep the memory allocated for later usage.
        trading_bot_cfg.clear();
    }
    // todo: cancel all pending orders
}

async fn update_single_order(cfg: SimpleCoinMarketMakerCfg, uuid: Uuid, _order: MakerOrder, key_trade_pair: String) {
    info!("need to update order: {} of {} - cfg: {}", uuid, key_trade_pair, cfg)
}

async fn process_bot_logic(ctx: &MmArc) {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(ctx).unwrap();
    // note: Copy the cfg here will not be expensive, and this will be thread safe.
    let cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await.clone();

    let mut memoization_pair_registry: HashSet<String> = HashSet::new();
    let maker_orders = retrieve_my_maker_orders(ctx).await;

    info!("nb_orders: {}", maker_orders.len());
    for (key, value) in maker_orders.into_iter() {
        let key_trade_pair = TradingPair::new(value.base.clone(), value.rel.clone());
        match cfg.get(&key_trade_pair.as_combination()) {
            Some(coin_cfg) => {
                update_single_order(coin_cfg.clone(), key, value.clone(), key_trade_pair.as_combination()).await;
                memoization_pair_registry.insert(key_trade_pair.as_combination());
            },
            _ => continue,
        }
        println!("{}", key);
    }
}

pub async fn lp_bot_loop(ctx: MmArc) {
    info!("lp_bot_loop successfully started");
    loop {
        // todo: this log should probably in debug
        info!("tick lp_bot_loop");
        if ctx.is_stopping() {
            // todo: can we cancel all the pending orders when the ctx is stopping or call tear_down ?
            break;
        }
        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if *states == TradingBotState::Stopping {
            *states = TradingBotState::Stopped;
            // todo: verify if there is a possible deadlock here if i use states inside tear_down_bot
            tear_down_bot(ctx).await;
            break;
        }
        drop(states);
        process_bot_logic(&ctx).await;
        Timer::sleep(30.0).await;
    }
    info!("lp_bot_loop successfully stopped");
}

pub async fn process_price_request() -> Result<(StatusCode, String, HeaderMap), MmError<PriceServiceRequestError>> {
    info!("Fetching price from: {}", KMD_PRICE_ENDPOINT);
    let (status, headers, body) = slurp_url(KMD_PRICE_ENDPOINT).await?;
    Ok((status, std::str::from_utf8(&body)?.trim().into(), headers))
}

async fn fetch_price_tickers(ctx: &MmArc) {
    let (status_code, body, _) = match process_price_request().await {
        Ok(x) => x,
        Err(_) => return,
    };
    if status_code == StatusCode::OK {
        let model: TickerInfosRegistry = match serde_json::from_str(&body) {
            Ok(model) => model,
            Err(_) => {
                error!("error when unparsing the price fetching answer");
                return;
            },
        };
        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(ctx).unwrap();
        let mut price_registry = simple_market_maker_bot_ctx.price_tickers_registry.lock().await;
        *price_registry = model;
        info!("registry size: {}", price_registry.len());
    } else {
        error!("error from price request: {} - {}", status_code, body);
    }
}

pub async fn lp_price_service_loop(ctx: MmArc) {
    info!("lp_price_service successfully started");
    loop {
        // todo: this log should probably in debug
        info!("tick lp_price_service_loop");
        if ctx.is_stopping() {
            break;
        }

        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if *states == TradingBotState::Stopping {
            info!("stop price service loop");
            break;
        }
        drop(states);
        fetch_price_tickers(&ctx).await;
        Timer::sleep(20.0).await;
    }
    info!("lp_price_service successfully stopped");
}

pub async fn start_simple_market_maker_bot(ctx: MmArc, req: StartSimpleMakerBotRequest) -> StartSimpleMakerBotResult {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if *states == TradingBotState::Running {
            return MmError::err(StartSimpleMakerBotError::AlreadyStarted);
        }
        let mut trading_bot_cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await;
        *trading_bot_cfg = req.cfg;
        *states = TradingBotState::Running;
    }

    info!("simple_market_maker_bot successfully started");
    spawn(lp_price_service_loop(ctx.clone()));
    spawn(lp_bot_loop(ctx.clone()));
    Ok(StartSimpleMakerBotRes {
        result: "Success".to_string(),
    })
}

pub async fn stop_simple_market_maker_bot(ctx: MmArc, _req: Json) -> StopSimpleMakerBotResult {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if *states == TradingBotState::Stopped {
            return MmError::err(StopSimpleMakerBotError::AlreadyStopped);
        } else if *states == TradingBotState::Stopping {
            return MmError::err(StopSimpleMakerBotError::AlreadyStopping);
        }

        *states = TradingBotState::Stopping;
    }
    info!("simple_market_maker_bot will stop within 30 seconds");
    Ok(StopSimpleMakerBotRes {
        result: "Success".to_string(),
    })
}
