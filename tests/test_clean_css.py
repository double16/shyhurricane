from shyhurricane.clean_css import (
    _clean_url,
    _normalize_color,
    _normalize_number,
    _normalize_selector,
    normalize_css,
)


def test_normalize_number_collapses_zero_px_and_integer_floats():
    assert _normalize_number("0px") == "0"
    assert _normalize_number("1.0") == "1"
    assert _normalize_number("1.25") == "1.25"
    assert _normalize_number("calc(100% - 1px)") == "calc(100% - 1px)"


def test_normalize_color_lowercases_and_shortens_hex():
    assert _normalize_color("#AABBCC") == "#abc"
    assert _normalize_color("#ABCDEF") == "#abcdef"
    assert _normalize_color("red") == "red"


def test_clean_url_removes_query_and_fragment():
    assert _clean_url('url("assets/app.css?v=123#hash")') == "url(assets/app.css)"
    assert _clean_url("url('/static/site.css#cache')") == "url(/static/site.css)"


def test_normalize_selector_collapses_spacing_around_combinators():
    assert _normalize_selector(" main   >   .card  +  a ") == "main>.card+a"
    assert _normalize_selector("body    .content") == "body .content"


def test_normalize_css_sorts_selectors_and_declarations_and_keeps_last_property():
    css = """
    .b, .a > span {
        color: #AABBCC;
        margin: 1.0;
        color: #FFFFFF;
        background: url("/app.css?v=1#x");
    }
    """

    assert normalize_css(css) == ".a>span,.b{background:url(/app.css);color:#fff;margin:1;}"


def test_normalize_css_handles_at_rules_errors_hashes_and_timestamps():
    css = """
    @media screen and (min-width: 1px) {
        color: #112233;
        z-index: 1.0;
    }
    @charset "utf-8";
    .token {
        content: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        updated: "2026-06-20 05:04:03";
    }
    }
    """

    assert normalize_css(css) == (
        '@media screen and (min-width: 1px){color:#123;z-index:1;}'
        '@charset "utf-8";'
        '.token{content:"<HASH>";updated:"<TIMESTAMP>";}'
    )
