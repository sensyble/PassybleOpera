//! Sans-IO HTTP for the sync code: the sync algorithms are `async` over a [`Transport`], run by a
//! blocking transport in the apps ([`block_on`]) or parked at each request by an [`Exchange`] in the
//! browser extension, so both drive the same code.

use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use crate::i18n::tr;
use crate::{PassError, Result};

/// One HTTP request for the host to send. `url` is complete (query included).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    // Never the Authorization header's value or the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpRequest {
    pub(crate) fn new(method: &str, url: String) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> HttpRequest {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub(crate) fn body(mut self, body: Vec<u8>) -> HttpRequest {
        self.body = body;
        self
    }
}

/// The host's answer to an [`HttpRequest`]: any status (errors too), the headers and the body.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header called `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// A 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Why the host got no HTTP answer (`fetch` threw, or timed out).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchFailure {
    /// No connection: offline, the name doesn't resolve, refused, reset, timed out.
    Unreachable,
    /// The address can't be used.
    BadAddress,
}

impl FetchFailure {
    /// `"bad_address"`, anything else (`"offline"`, `"timeout"`, ...) is [`FetchFailure::Unreachable`].
    pub fn from_name(name: &str) -> FetchFailure {
        match name {
            "bad_address" => FetchFailure::BadAddress,
            _ => FetchFailure::Unreachable,
        }
    }
}

/// `{action}: …`, the shape of the core's network errors, for a request to `url` that got no answer.
pub(crate) fn failure_error(action: &str, failure: FetchFailure, url: &str) -> PassError {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_else(|| url.to_string());
    PassError::Network(match failure {
        FetchFailure::Unreachable => {
            format!("{action}: {}", tr!("pinning.cant_connect", host = host))
        }
        FetchFailure::BadAddress => format!("{action}: {}", tr!("server.invalid_address")),
    })
}

/// What the sync code sends its requests through. `action` names the step for error messages.
pub(crate) trait Transport {
    async fn send(&self, request: HttpRequest, action: &str) -> Result<HttpResponse>;
}

/// Runs a future whose transport never waits (the apps' blocking one) to its end.
#[cfg(feature = "webdav")]
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(out) => out,
        Poll::Pending => unreachable!("a blocking transport never waits"),
    }
}

/// Where an [`Exchange`]'s future and its host meet.
enum Slot {
    Idle,
    Out(HttpRequest, String),
    In(Result<HttpResponse>),
}

/// The transport of an [`Exchange`]: puts the request in the slot and waits for the answer.
pub(crate) struct HostTransport {
    slot: Rc<RefCell<Slot>>,
}

struct Parked(Rc<RefCell<Slot>>);

impl Future for Parked {
    type Output = Result<HttpResponse>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut slot = self.0.borrow_mut();
        match std::mem::replace(&mut *slot, Slot::Idle) {
            Slot::In(answer) => Poll::Ready(answer),
            other => {
                *slot = other;
                Poll::Pending
            }
        }
    }
}

impl Transport for HostTransport {
    async fn send(&self, request: HttpRequest, action: &str) -> Result<HttpResponse> {
        *self.slot.borrow_mut() = Slot::Out(request, action.to_string());
        Parked(self.slot.clone()).await
    }
}

/// What an [`Exchange`] needs next.
#[derive(Debug)]
pub enum Step<T> {
    /// Send this request, then call [`Exchange::on_response`] (any status) or
    /// [`Exchange::on_failure`] (no answer).
    Send(HttpRequest),
    /// Finished: the same result the apps' blocking call returns.
    Done(Result<T>),
}

/// A sync operation the host drives request by request. Not `Send`: one JavaScript thread drives it.
/// Dropping it abandons the operation (each merge is one step, so nothing is left half-written).
pub struct Exchange<T> {
    future: Option<Pin<Box<dyn Future<Output = Result<T>>>>>,
    slot: Rc<RefCell<Slot>>,
    /// The action and URL of the request out at the host, for [`Exchange::on_failure`].
    waiting: Option<(String, String)>,
}

impl<T> fmt::Debug for Exchange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("done", &self.future.is_none())
            .field("waiting", &self.waiting.as_ref().map(|(_, url)| url))
            .finish()
    }
}

impl<T: 'static> Exchange<T> {
    /// Starts `make(transport)` and returns the exchange with its first step.
    pub(crate) fn start<F>(make: impl FnOnce(HostTransport) -> F) -> (Exchange<T>, Step<T>)
    where
        F: Future<Output = Result<T>> + 'static,
    {
        let slot = Rc::new(RefCell::new(Slot::Idle));
        let future = make(HostTransport { slot: slot.clone() });
        let mut exchange = Exchange {
            future: Some(Box::pin(future)),
            slot,
            waiting: None,
        };
        let first = exchange.poll();
        (exchange, first)
    }

    /// The host's answer to the request of the last [`Step::Send`].
    pub fn on_response(&mut self, response: HttpResponse) -> Step<T> {
        if self.waiting.take().is_none() {
            return self.misused();
        }
        *self.slot.borrow_mut() = Slot::In(Ok(response));
        self.poll()
    }

    /// The request of the last [`Step::Send`] got no answer.
    pub fn on_failure(&mut self, failure: FetchFailure) -> Step<T> {
        let Some((action, url)) = self.waiting.take() else {
            return self.misused();
        };
        *self.slot.borrow_mut() = Slot::In(Err(failure_error(&action, failure, &url)));
        self.poll()
    }

    /// Whether [`Step::Done`] was returned already.
    pub fn is_done(&self) -> bool {
        self.future.is_none()
    }

    fn misused(&mut self) -> Step<T> {
        self.future = None;
        Step::Done(Err(PassError::InvalidInput(
            "no request is waiting for an answer".into(),
        )))
    }

    fn poll(&mut self) -> Step<T> {
        let Some(future) = self.future.as_mut() else {
            return self.misused();
        };
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(out) => {
                self.future = None;
                Step::Done(out)
            }
            Poll::Pending => match std::mem::replace(&mut *self.slot.borrow_mut(), Slot::Idle) {
                Slot::Out(request, action) => {
                    self.waiting = Some((action, request.url.clone()));
                    Step::Send(request)
                }
                _ => {
                    self.future = None;
                    Step::Done(Err(PassError::InvalidInput(
                        "the operation waited on something else than a request".into(),
                    )))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn two_requests<T: Transport>(http: T) -> Result<(u16, u16)> {
        let a = http
            .send(
                HttpRequest::new("GET", "https://example.com/a".into()),
                "first",
            )
            .await?;
        let b = http
            .send(
                HttpRequest::new("PUT", "https://example.com/b".into()).body(vec![1, 2]),
                "second",
            )
            .await?;
        Ok((a.status, b.status))
    }

    fn sent<T: fmt::Debug>(step: Step<T>) -> HttpRequest {
        match step {
            Step::Send(request) => request,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_exchange_hands_out_each_request_and_resumes_with_the_answer() {
        let (mut exchange, first) = Exchange::start(two_requests);
        let a = sent(first);
        assert_eq!(
            (a.method.as_str(), a.url.as_str()),
            ("GET", "https://example.com/a")
        );
        let b = sent(exchange.on_response(HttpResponse {
            status: 200,
            ..Default::default()
        }));
        assert_eq!(b.body, vec![1, 2]);
        assert!(!exchange.is_done());
        match exchange.on_response(HttpResponse {
            status: 404,
            ..Default::default()
        }) {
            Step::Done(Ok((200, 404))) => {}
            other => panic!("{other:?}"),
        }
        assert!(exchange.is_done());
        // Answering again is a mistake, not a panic.
        assert!(matches!(
            exchange.on_response(HttpResponse::default()),
            Step::Done(Err(PassError::InvalidInput(_)))
        ));
    }

    #[test]
    fn no_answer_is_a_network_error_naming_the_host() {
        let (mut exchange, first) = Exchange::start(two_requests);
        sent(first);
        match exchange.on_failure(FetchFailure::Unreachable) {
            Step::Done(Err(PassError::Network(message))) => {
                assert!(message.starts_with("first: "), "{message}");
                assert!(message.contains("example.com"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            FetchFailure::from_name("timeout"),
            FetchFailure::Unreachable
        );
        assert_eq!(
            FetchFailure::from_name("bad_address"),
            FetchFailure::BadAddress
        );
    }

    #[test]
    fn requests_never_show_their_secrets_in_debug_output() {
        let request = HttpRequest::new("GET", "https://example.com/".into())
            .header("Authorization", "Bearer ya29.secret")
            .body(b"vault".to_vec());
        let shown = format!("{request:?}");
        assert!(
            !shown.contains("ya29") && !shown.contains("vault"),
            "{shown}"
        );
        assert!(shown.contains("Authorization"));
    }
}
