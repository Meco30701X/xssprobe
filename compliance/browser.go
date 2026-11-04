package compliance

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// InstallBrowserPolicy intercepts browser requests so scope, rate limiting,
// and operator credentials are applied at the actual network boundary.
func InstallBrowserPolicy(ctx context.Context, targetURL string, cookies []string, headers map[string]string, checks *ComplianceContext, limiter *RateLimiter) error {
	target, err := url.Parse(targetURL)
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return fmt.Errorf("invalid browser target URL: %s", targetURL)
	}
	if limiter == nil && checks != nil {
		limiter = checks.Limiter
	}
	cookieURL := *target
	cookieURL.Fragment = ""
	cookieURL.RawFragment = ""

	var cookieActions []chromedp.Action
	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		cookieActions = append(cookieActions, chromedp.ActionFunc(func(actionCtx context.Context) error {
			return network.SetCookie(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])).
				WithURL(cookieURL.String()).WithPath("/").Do(actionCtx)
		}))
	}
	if len(cookieActions) > 0 {
		if err := chromedp.Run(ctx, cookieActions...); err != nil {
			return fmt.Errorf("auth cookie setup failed: %w", err)
		}
	}

	chromedp.ListenTarget(ctx, func(event interface{}) {
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok || paused.Request == nil {
			return
		}

		go func() {
			requestURL, parseErr := url.Parse(paused.Request.URL)
			if parseErr != nil {
				_ = runBrowserAction(ctx, func(actionCtx context.Context) error {
					return fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(actionCtx)
				})
				return
			}
			// Page-local resources do not leave the browser and are not subject
			// to domain scope or HTTP rate limits. All other non-HTTP schemes
			// are blocked to prevent handing requests to external handlers.
			if requestURL.Scheme == "data" || requestURL.Scheme == "blob" || requestURL.Scheme == "about" {
				_ = runBrowserAction(ctx, func(actionCtx context.Context) error {
					return fetch.ContinueRequest(paused.RequestID).Do(actionCtx)
				})
				return
			}
			if requestURL.Scheme != "http" && requestURL.Scheme != "https" {
				_ = runBrowserAction(ctx, func(actionCtx context.Context) error {
					return fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(actionCtx)
				})
				return
			}
			if checks != nil {
				if err := checks.CheckURL(paused.Request.URL, "browser"); err != nil {
					_ = runBrowserAction(ctx, func(actionCtx context.Context) error {
						return fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(actionCtx)
					})
					return
				}
			}
			if limiter != nil {
				limiter.Wait()
			}

			continuation := fetch.ContinueRequest(paused.RequestID)
			if sameOrigin(target, paused.Request.URL) && len(headers) > 0 {
				entries := make([]*fetch.HeaderEntry, 0, len(paused.Request.Headers)+len(headers))
				for name, value := range paused.Request.Headers {
					if _, overridden := headerValue(headers, name); overridden {
						continue
					}
					entries = append(entries, &fetch.HeaderEntry{Name: name, Value: fmt.Sprint(value)})
				}
				for name, value := range headers {
					entries = append(entries, &fetch.HeaderEntry{Name: name, Value: value})
				}
				continuation = continuation.WithHeaders(entries)
			}
			if err := runBrowserAction(ctx, func(actionCtx context.Context) error {
				return continuation.Do(actionCtx)
			}); err != nil && checks != nil {
				checks.LogError(paused.Request.URL, "browser", "failed to continue intercepted request: "+err.Error())
			}
		}()
	})

	if err := chromedp.Run(ctx, fetch.Enable().WithPatterns([]*fetch.RequestPattern{{
		URLPattern:   "*",
		RequestStage: fetch.RequestStageRequest,
	}})); err != nil {
		return fmt.Errorf("enable browser request interception: %w", err)
	}
	return nil
}

// runBrowserAction executes CDP commands inside chromedp's target executor.
// Calling cdproto Do directly with the outer context can return ErrInvalidContext
// and leave an intercepted browser request paused indefinitely.
func runBrowserAction(ctx context.Context, action func(context.Context) error) error {
	state := chromedp.FromContext(ctx)
	if state == nil || state.Target == nil {
		return fmt.Errorf("browser target is not initialized")
	}
	// Do not queue this command through chromedp.Run: navigation may be waiting
	// for the very request paused by Fetch interception, which would deadlock the
	// serialized action runner. The target executor can service it immediately.
	return action(cdp.WithExecutor(ctx, state.Target))
}

func sameOrigin(target *url.URL, rawURL string) bool {
	request, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(target.Scheme, request.Scheme) &&
		strings.EqualFold(target.Host, request.Host)
}

func headerValue(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}
