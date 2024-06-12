use roc_std::{RocList, RocStr};
use std::{iter::FromIterator, time::Duration};

pub fn send_req(roc_request: &roc_app::InternalRequest) -> roc_app::InternalResponse {
    let mut builder = reqwest::blocking::ClientBuilder::new();

    if roc_request.timeout.is_TimeoutMilliseconds() {
        let ms: u64 = roc_request.timeout.clone().unwrap_TimeoutMilliseconds();
        builder = builder.timeout(Duration::from_millis(ms));
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => {
            return roc_app::InternalResponse {
                status: 500,
                body: RocList::empty(),
                headers: RocList::empty(),
            }; // TLS backend cannot be initialized
        }
    };

    let method = {
        use reqwest::Method;
        use roc_app::InternalMethod::*;

        match roc_request.method {
            Connect => Method::CONNECT,
            Delete => Method::DELETE,
            Get => Method::GET,
            Head => Method::HEAD,
            Options => Method::OPTIONS,
            Patch => Method::PATCH,
            Post => Method::POST,
            Put => Method::PUT,
            Trace => Method::TRACE,
        }
    };

    let url = roc_request.url.as_str();

    let mut req_builder = client.request(method, url);

    for header in roc_request.headers.iter() {
        req_builder = req_builder.header(header.name.as_str(), header.value.as_slice());
    }

    let mime_type_str = roc_request.mimeType.as_str();
    let bytes = roc_request.body.as_slice().to_vec();

    req_builder = req_builder.header("Content-Type", mime_type_str);
    req_builder = req_builder.body(bytes);

    let request = match req_builder.build() {
        Ok(req) => req,
        Err(err) => {
            return roc_app::InternalResponse {
                status: 400,
                body: RocList::from_slice(err.to_string().as_bytes()),
                headers: RocList::empty(),
            }; // Bad Request 400
        }
    };

    match client.execute(request) {
        Ok(response) => {
            let headers_iter =
                response
                    .headers()
                    .iter()
                    .map(|(name, value)| roc_app::InternalHeader {
                        name: RocStr::from(name.as_str()),
                        value: RocList::from(value.as_bytes()),
                    });

            let headers = RocList::from_iter(headers_iter);

            let status = response.status().as_u16();
            let bytes = response.bytes().unwrap_or_default();
            let body: RocList<u8> = RocList::from_iter(bytes.into_iter());

            roc_app::InternalResponse {
                status,
                body,
                headers,
            }
        }

        Err(err) => {
            if err.is_timeout() {
                roc_app::InternalResponse {
                    status: 408, // 408 Request Timeout
                    body: RocList::from_slice(err.to_string().as_bytes()),
                    headers: RocList::empty(),
                }
            } else if err.is_request() {
                roc_app::InternalResponse {
                    status: 400, // 400 Bad Request
                    body: RocList::from_slice(err.to_string().as_bytes()),
                    headers: RocList::empty(),
                }
            } else {
                // TODO handle more errors
                roc_app::InternalResponse {
                    status: 404, // 404 Not Found
                    body: RocList::from_slice(err.to_string().as_bytes()),
                    headers: RocList::empty(),
                }
            }
        }
    }
}
