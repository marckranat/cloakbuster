/**
 * Hostnames for third-party iframes that often look “suspicious” in heuristics
 * (1×1, display:none, off-site) but are usually legitimate ads, analytics, or CMS embeds.
 *
 * Treat as a **curated allowlist**, not a security guarantee — compromised
 * sites can still load bad content through known CDNs. We still emit a CSP advisory
 * for cross-origin frames from these hosts.
 *
 * References (when extending):
 * - AddToAny (WordPress social sharing): https://wordpress.org/plugins/addtoany/
 * - MailerLite webforms: https://www.mailerlite.com/help/
 * - Infolinks: common contextual-ads / related-links vendor for publishers
 * - Jetpack / WordPress.com embeds & widgets: https://jetpack.com/ — iframes often
 *   under *.wordpress.com or *.wp.com (e.g. widgets.wp.com).
 * - Mailchimp embedded forms / assets: https://mailchimp.com/help/
 * - Contact Form 7: https://contactform7.com/ — core form is first-party; third-party
 *   iframes usually reCAPTCHA (google.com / recaptcha.net) or Cloudflare Turnstile
 *   (challenges.cloudflare.com; allowlisted as exact host only), or hCaptcha.
 */

const EXACT_HOSTS = new Set([
  "imasdk.googleapis.com",
  "tpc.googlesyndication.com",
  "pagead2.googlesyndication.com",
  "www.googletagmanager.com",
  "www.google.com",
  "www.youtube.com",
  "www.youtube-nocookie.com",
  "player.vimeo.com",
  "platform.twitter.com",
  "syndication.twitter.com",
  "cdn.syndication.twimg.com",
  "connect.facebook.net",
  "www.facebook.com",
  "staticxx.facebook.com",
  "bat.bing.com",
  "www.reddit.com",
  "www.redditmedia.com",
  "accounts.google.com",
  "fundingchoicesmessages.google.com",
  "app.mailerlite.com",
  "trc.taboola.com",
  "cdn.taboola.com",
  "widgets.taboola.com",
  "gum.criteo.com",
  "bidder.criteo.com",
  "dynamic.criteo.com",
  "hbopenbid.pubmatic.com",
  "sshowads.pubmatic.com",
  /** Cloudflare Turnstile (often paired with Contact Form 7) */
  "challenges.cloudflare.com",
]);

const SUFFIX_HOSTS = [
  "doubleclick.net",
  "googleadservices.com",
  "googlesyndication.com",
  "googletagservices.com",
  "2mdn.net",
  "bing.com",
  "facebook.com",
  "fbcdn.net",
  "twimg.com",
  "linkedin.com",
  "licdn.com",
  "instagram.com",
  "tiktok.com",
  "youtube.com",
  "snapchat.com",
  "amazon-adsystem.com",
  "ads-twitter.com",
  "taboola.com",
  "criteo.com",
  "pubmatic.com",
  /** AddToAny “utility” iframe (e.g. static.addtoany.com) */
  "addtoany.com",
  /** Infolinks sync / ad router iframes */
  "infolinks.com",
  /** Jetpack / WordPress.com: widgets, embeds, CDN (widgets.wp.com, i0.wp.com, …) */
  "wp.com",
  /** Jetpack oEmbed sandbox, WordPress.com-hosted embeds */
  "wordpress.com",
  /** Jetpack marketing / config iframes */
  "jetpack.com",
  /** Mailchimp signup embeds (us1.list-manage.com, …) */
  "list-manage.com",
  "mailchimp.com",
  "chimpstatic.com",
  /** Google reCAPTCHA (Contact Form 7, Jetpack, etc.) */
  "recaptcha.net",
  /** hCaptcha (common Contact Form 7 add-on / integration) */
  "hcaptcha.com",
] as const;

export function isBenignThirdPartyIframeHost(hostname: string): boolean {
  const h = hostname.replace(/\.$/, "").toLowerCase();
  if (!h) return false;
  if (EXACT_HOSTS.has(h)) return true;
  for (const s of SUFFIX_HOSTS) {
    if (h === s || h.endsWith(`.${s}`)) return true;
  }
  return false;
}
