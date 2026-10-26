import pytest

from hunter.normalize import (
    CRYPTO, DOMAIN, EMAIL, IP, PAYMENT, PHONE, SOCIAL, TELEGRAM, URL, WHATSAPP,
    InvalidIndicator, derived_domain, is_public, normalize,
)


def canon(value, **kw):
    ind = normalize(value, **kw)
    return ind.type, ind.canonical


@pytest.mark.parametrize("value", [
    "MPESA-EXAMPLE.COM", "mpesa-example.com/", "https://mpesa-example.com",
    "HTTP://WWW.Mpesa-Example.com/", "  mpesa-example.com  ", "mpesa-example.com.",
])
def test_domain_spellings_collapse_to_one_entity(value):
    assert canon(value) == (DOMAIN, "mpesa-example.com")


def test_url_with_path_stays_url_and_derives_domain():
    ind = normalize("https://Mpesa-Example.com/verify?x=1#frag")
    assert (ind.type, ind.canonical) == (URL, "https://mpesa-example.com/verify?x=1")
    assert derived_domain(ind).canonical == "mpesa-example.com"


def test_default_ports_dropped_odd_ports_kept():
    assert canon("https://a-b.example:443/x")[1] == "https://a-b.example/x"
    assert canon("http://a-b.example:8080/x")[1] == "http://a-b.example:8080/x"


def test_idn_is_punycoded():
    assert canon("https://mpésa.example/")[1] == "xn--mpsa-cpa.example"


@pytest.mark.parametrize("value", ["localhost", "notadomain", "a..b.com", "-bad-.com", "ftp://x.com/a", "ftp://example.org/a", ""])
def test_invalid_domains_raise(value):
    with pytest.raises(InvalidIndicator):
        normalize(value)


@pytest.mark.parametrize("value", ["0712345678", "254712345678", "+254712345678", "+254 712 345 678",
                                   "0712-345-678", "tel:+254712345678", "00254712345678"])
def test_kenyan_phone_equivalence(value):
    assert canon(value) == (PHONE, "+254712345678")


def test_local_number_without_market_is_not_guessed():
    with pytest.raises(InvalidIndicator):
        normalize("0712345678", region=None)
    with pytest.raises(InvalidIndicator):
        normalize("712345678")


def test_bad_kenyan_length_rejected():
    with pytest.raises(InvalidIndicator):
        normalize("+2547123456")


def test_other_market_e164_kept():
    assert canon("+255 754 000 000") == (PHONE, "+255754000000")


@pytest.mark.parametrize("value", [
    "https://wa.me/254700000000", "wa.me/254700000000?text=hi",
    "https://api.whatsapp.com/send?phone=254700000000&text=x",
    "whatsapp://send?phone=+254700000000",
])
def test_whatsapp_links(value):
    assert canon(value) == (WHATSAPP, "+254700000000")


def test_whatsapp_group_and_business_links_and_numberless():
    assert canon("https://chat.whatsapp.com/AbC123") == (WHATSAPP, "group:AbC123")
    assert canon("https://wa.me/message/XyZ9") == (WHATSAPP, "link:XyZ9")
    with pytest.raises(InvalidIndicator):
        normalize("https://wa.me/?text=hello")


def test_whatsapp_hint_takes_bare_number():
    assert canon("0700000000", hint="whatsapp") == (WHATSAPP, "+254700000000")


@pytest.mark.parametrize("value", ["https://t.me/Mpesa_Support", "t.me/mpesa_support", "https://t.me/s/mpesa_support",
                                   "tg://resolve?domain=Mpesa_Support"])
def test_telegram_handles(value):
    assert canon(value) == (TELEGRAM, "mpesa_support")


def test_telegram_bare_handle_needs_hint_and_reserved_rejected():
    with pytest.raises(InvalidIndicator):
        normalize("@mpesa_support")
    assert canon("@Mpesa_Support", hint="telegram") == (TELEGRAM, "mpesa_support")
    assert canon("https://t.me/+AbCdEf123") == (TELEGRAM, "invite:AbCdEf123")
    with pytest.raises(InvalidIndicator):
        normalize("https://t.me/share/url?url=x")


def test_email_and_mailto():
    assert canon("Help@MPESA-Example.COM") == (EMAIL, "help@mpesa-example.com")
    assert canon("mailto:help@mpesa-example.com?subject=x") == (EMAIL, "help@mpesa-example.com")
    assert derived_domain(normalize("a@b-c.example")).canonical == "b-c.example"


def test_ip_forms():
    assert canon("203.0.113.9") == (IP, "203.0.113.9")
    assert canon("[2001:DB8::1]") == (IP, "2001:db8::1")
    assert canon("::ffff:203.0.113.9") == (IP, "203.0.113.9")
    with pytest.raises(InvalidIndicator):
        normalize("203.0.113.9", hint="domain")


def test_crypto_addresses():
    assert canon("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD")[0] == CRYPTO
    assert canon("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD")[1].startswith("evm:0xabcdef")
    assert canon("1BoatSLRHtKNngkdXEeobR76b53LETtpyT") == (CRYPTO, "btc:1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert canon("TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE") == (CRYPTO, "tron:TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE")
    with pytest.raises(InvalidIndicator):
        normalize("0x123", hint="crypto")


def test_payment_identifiers():
    assert canon("Paybill: 123456") == (PAYMENT, "paybill:123456")
    assert canon("till number 654321") == (PAYMENT, "till:654321")
    assert canon("pay bill 123456") == (PAYMENT, "paybill:123456")


def test_social_links():
    assert canon("https://www.facebook.com/MpesaKenya/") == (SOCIAL, "facebook:mpesakenya")
    assert canon("https://facebook.com/profile.php?id=1000123") == (SOCIAL, "facebook:id:1000123")
    assert canon("https://twitter.com/MpesaKenya") == (SOCIAL, "x:mpesakenya")
    assert canon("https://tiktok.com/@some.one") == (SOCIAL, "tiktok:some.one")
    assert canon("@MpesaKenya", hint="twitter") == (SOCIAL, "x:mpesakenya")
    with pytest.raises(InvalidIndicator):
        normalize("@MpesaKenya", hint="social")


def test_social_share_link_falls_back_to_url():
    assert normalize("https://facebook.com/sharer/sharer.php?u=x").type == URL


def test_is_public():
    for value in ["http://127.0.0.1/x", "http://10.0.0.5/", "http://169.254.169.254/latest",
                  "http://[::1]/", "http://intranet.local/x", "http://192.168.1.1/"]:
        assert not is_public(normalize(value)), value
    # 203.0.113.0/24 is a documentation range and Python treats it as non-public.
    assert is_public(normalize("http://8.8.8.8/x"))
    assert not is_public(normalize("http://203.0.113.9/x"))
    assert is_public(normalize("mpesa-example.com"))
    assert is_public(normalize("+254712345678"))


def test_unknown_hint_and_type_errors():
    with pytest.raises(InvalidIndicator):
        normalize("x.com", hint="nope")
    with pytest.raises(InvalidIndicator):
        normalize(None)  # type: ignore[arg-type]
