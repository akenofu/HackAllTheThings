# SEO Optimization
- [The Open Graph protocol (ogp.me)](https://ogp.me/)
- Canonical Urls
- Meta tags in website e.g. description, author, etc.

Example
```html
{% extends "base.html" %}
{%- block site_meta %}
<link rel="canonical" href="https://notes.akenofu.me/">
{%- endblock %}


{% block extrahead %}
  {% set title = config.site_name %}
  {% if page and page.meta and page.meta.title %}
    {% set title = title ~ " - " ~ page.meta.title %}
  {% elif page and page.title and not page.is_homepage %}
    {% set title = title ~ " - " ~ page.title %}
  {% endif %}
  <meta property="og:type" content="website" />
  <meta property="og:title" content="{{ title }}" />
  <meta property="og:description" content="{{ config.site_description }}" />
  
  <!---
    TBD
    One day I will stop hardcoding this
  <meta property="og:url" content="https://notes.akenofu.me" />
  -->

  <meta property="og:image" content="https://notes.akenofu.me/Screenshots/me.gif" />
  <meta property="og:image:type" content="image/png" />
  <meta property="og:image:width" content="480" />
  <meta property="og:image:height" content="270" />
  

  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="{{ title }}" />
  <meta name="twitter:description" content="{{ config.site_description }}" />
  <meta name="twitter:image" content="https://notes.akenofu.me/Screenshots/me.gif" />

{% endblock %}
```