# ZAP Scanning Report


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 6 |
| Low | 4 |
| Informational | 9 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Absence of Anti-CSRF Tokens | Medium | 2 |
| Anti-CSRF Tokens Check | Medium | 3 |
| Bypassing 403 | Medium | 3 |
| Content Security Policy (CSP) Header Not Set | Medium | 2 |
| Sub Resource Integrity Attribute Missing | Medium | 2 |
| Vulnerable JS Library | Medium | 5 |
| Cookie No HttpOnly Flag | Low | 3 |
| Cookie without SameSite Attribute | Low | 3 |
| Dangerous JS Functions | Low | 4 |
| Permissions Policy Header Not Set | Low | 11 |
| Authentication Request Identified | Informational | 1 |
| Cookie Slack Detector | Informational | 81 |
| Information Disclosure - Sensitive Information in URL | Informational | 2 |
| Information Disclosure - Suspicious Comments | Informational | 16 |
| Modern Web Application | Informational | 2 |
| Non-Storable Content | Informational | 1 |
| Session Management Response Identified | Informational | 5 |
| Storable but Non-Cacheable Content | Informational | 10 |
| User Agent Fuzzer | Informational | 12 |




## Alert Detail



### [ Absence of Anti-CSRF Tokens ](https://www.zaproxy.org/docs/alerts/10202/)



##### Medium (Low)

### Description

No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form ng-submit="authenticatePassword()">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token] was found in the following HTML form: [Form 1: "password" "user" ].`
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form ng-submit="authenticatePassword()">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token] was found in the following HTML form: [Form 1: "password" "user" ].`

Instances: 2

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ http://projects.webappsec.org/Cross-Site-Request-Forgery ](http://projects.webappsec.org/Cross-Site-Request-Forgery)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Anti-CSRF Tokens Check ](https://www.zaproxy.org/docs/alerts/20012/)



##### Medium (Medium)

### Description

A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: http://127.0.0.1:8384
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form ng-submit="authenticatePassword()">`
  * Other Info: ``
* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form ng-submit="authenticatePassword()">`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form ng-submit="authenticatePassword()">`
  * Other Info: ``

Instances: 3

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ http://projects.webappsec.org/Cross-Site-Request-Forgery ](http://projects.webappsec.org/Cross-Site-Request-Forgery)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 1

### [ Bypassing 403 ](https://www.zaproxy.org/docs/alerts/40038/)



##### Medium (Medium)

### Description

Bypassing 403 endpoints may be possible, the scan rule sent a payload that caused the response to be accessible (status code 200).

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: `x-original-url: /rest`
  * Evidence: ``
  * Other Info: `http://127.0.0.1:8384/rest`
* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: `x-original-url: /rest/debug`
  * Evidence: ``
  * Other Info: `http://127.0.0.1:8384/rest/debug`
* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: `x-original-url: /rest/debug/support`
  * Evidence: ``
  * Other Info: `http://127.0.0.1:8384/rest/debug/support`

Instances: 3

### Solution



### Reference


* [ https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/ ](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)
* [ https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf ](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
* [ https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass ](https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass)



#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ http://www.w3.org/TR/CSP/ ](http://www.w3.org/TR/CSP/)
* [ http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html ](http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html)
* [ http://www.html5rocks.com/en/tutorials/security/content-security-policy/ ](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
* [ http://caniuse.com/#feat=contentsecuritypolicy ](http://caniuse.com/#feat=contentsecuritypolicy)
* [ http://content-security-policy.com/ ](http://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Sub Resource Integrity Attribute Missing ](https://www.zaproxy.org/docs/alerts/90003/)



##### Medium (High)

### Description

The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content. 

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link rel="shortcut icon" href="assets/img/favicon-{{syncthingStatus()}}.png" type="image/x-icon"/>`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link rel="shortcut icon" href="assets/img/favicon-{{syncthingStatus()}}.png" type="image/x-icon"/>`
  * Other Info: ``

Instances: 2

### Solution

Provide a valid integrity attribute to the tag.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity ](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)


#### CWE Id: [ 345 ](https://cwe.mitre.org/data/definitions/345.html)


#### WASC Id: 15

#### Source ID: 3

### [ Vulnerable JS Library ](https://www.zaproxy.org/docs/alerts/10003/)



##### Medium (Medium)

### Description

The identified library jquery, version 2.2.2 is vulnerable.

* URL: http://127.0.0.1:8384/vendor/angular/angular.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `http://errors.angularjs.org/1.3.20/`
  * Other Info: `CVE-2023-26116
CVE-2022-25869
CVE-2019-14863
CVE-2020-7676
CVE-2023-26117
CVE-2019-10768
CVE-2023-26118
`
* URL: http://127.0.0.1:8384/vendor/bootstrap/js/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `* Bootstrap v3.3.5`
  * Other Info: `CVE-2019-8331
CVE-2018-14041
CVE-2018-20677
CVE-2018-20676
CVE-2018-14042
CVE-2016-10735
`
* URL: http://127.0.0.1:8384/vendor/fancytree/jquery.fancytree-all-deps.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/*! jQuery UI - v1.12.1`
  * Other Info: `CVE-2021-41184
CVE-2021-41183
CVE-2021-41182
CVE-2022-31160
`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `jquery-2.2.2.js`
  * Other Info: `CVE-2020-11023
CVE-2020-11022
CVE-2015-9251
CVE-2019-11358
CVE-2020-23064
`
* URL: http://127.0.0.1:8384/vendor/moment/moment.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `//! moment.js
//! version : 2.19.4`
  * Other Info: `CVE-2022-31129
CVE-2022-24785
`

Instances: 5

### Solution

Please upgrade to the latest version of jquery.

### Reference


* [ https://github.com/jquery/jquery/issues/2432 ](https://github.com/jquery/jquery/issues/2432)
* [ http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/ ](http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/)
* [ http://research.insecurelabs.org/jquery/test/ ](http://research.insecurelabs.org/jquery/test/)
* [ https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ ](https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/)
* [ https://nvd.nist.gov/vuln/detail/CVE-2019-11358 ](https://nvd.nist.gov/vuln/detail/CVE-2019-11358)
* [ https://nvd.nist.gov/vuln/detail/CVE-2015-9251 ](https://nvd.nist.gov/vuln/detail/CVE-2015-9251)
* [ https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b ](https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b)
* [ https://bugs.jquery.com/ticket/11974 ](https://bugs.jquery.com/ticket/11974)
* [ https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/ ](https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/)
* [ https://github.com/jquery/jquery.com/issues/162 ](https://github.com/jquery/jquery.com/issues/162)


#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### Source ID: 3

### [ Cookie No HttpOnly Flag ](https://www.zaproxy.org/docs/alerts/10010/)



##### Low (Medium)

### Description

A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``
* URL: http://127.0.0.1:8384/robots.txt
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``

Instances: 3

### Solution

Ensure that the HttpOnly flag is set for all cookies.

### Reference


* [ https://owasp.org/www-community/HttpOnly ](https://owasp.org/www-community/HttpOnly)


#### CWE Id: [ 1004 ](https://cwe.mitre.org/data/definitions/1004.html)


#### WASC Id: 13

#### Source ID: 3

### [ Cookie without SameSite Attribute ](https://www.zaproxy.org/docs/alerts/10054/)



##### Low (Medium)

### Description

A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``
* URL: http://127.0.0.1:8384/robots.txt
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Set-Cookie: CSRF-Token-C4JT7`
  * Other Info: ``

Instances: 3

### Solution

Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

### Reference


* [ https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site ](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site)


#### CWE Id: [ 1275 ](https://cwe.mitre.org/data/definitions/1275.html)


#### WASC Id: 13

#### Source ID: 3

### [ Dangerous JS Functions ](https://www.zaproxy.org/docs/alerts/10110/)



##### Low (Low)

### Description

A dangerous JS function seems to be in use that would leave the site vulnerable.

* URL: http://127.0.0.1:8384/vendor/angular/angular-dirPagination.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval`
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular-sanitize.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `trustAsHtml`
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `trustAsHtml`
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval`
  * Other Info: ``

Instances: 4

### Solution

See the references for security advice on the use of these functions.

### Reference


* [ https://angular.io/guide/security ](https://angular.io/guide/security)


#### CWE Id: [ 749 ](https://cwe.mitre.org/data/definitions/749.html)


#### Source ID: 3

### [ Permissions Policy Header Not Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/syncthing/core/module.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/syncthing/development/logbar.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular-dirPagination.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular-sanitize.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate-loader-static-files.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/bootstrap/js/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/daterangepicker/daterangepicker.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/vendor/moment/moment.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
* [ https://developer.chrome.com/blog/feature-policy/ ](https://developer.chrome.com/blog/feature-policy/)
* [ https://scotthelme.co.uk/a-new-security-header-feature-policy/ ](https://scotthelme.co.uk/a-new-security-header-feature-policy/)
* [ https://w3c.github.io/webappsec-feature-policy/ ](https://w3c.github.io/webappsec-feature-policy/)
* [ https://www.smashingmagazine.com/2018/12/feature-policy/ ](https://www.smashingmagazine.com/2018/12/feature-policy/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (Low)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: `user`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=user
userValue=ZAP
passwordParam=password
referer=http://127.0.0.1:8384/`

Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Cookie Slack Detector ](https://www.zaproxy.org/docs/alerts/90027/)



##### Informational (Low)

### Description

Repeated GET requests: drop a different cookie each time, followed by normal request with all cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where cookie based authentication/attributes are not actually enforced.

* URL: http://127.0.0.1:8384
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('advanced
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('advanced/folder-ignoredelete'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('intro
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('intro/gui'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BdocsURL(&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%257B%257BremoteGUIAddress(deviceCfg&29.replace('%2525',%2520'%252525'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/css/overrides.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/css/theme.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/css/tree.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/font
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/font/raleway.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/img
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/img/favicon-%257B%257BsyncthingStatus(&29%257D%257D.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/img/favicon-default.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/img/logo-horizontal.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/img/safari-pinned-tab.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/lang
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/lang/prettyprint.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/assets/lang/valid-langs.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/meta.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/rest
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/rest/debug/support
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/app.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/alwaysNumberFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/basenameFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/binaryFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/durationFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/eventService.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/identiconDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/languageSelectDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/localeNumberFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/localeService.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/metricFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/modalDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/module.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/notificationDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/pathIsSubDirDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/percentFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/popoverDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/syncthingController.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/tooltipDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/uncamelFilter.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/uniqueFolderDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/core/validDeviceidDirective.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/development
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/syncthing/development/logbar.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular/angular-dirPagination.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular/angular-sanitize.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate-loader-static-files.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/angular/angular.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/bootstrap
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/bootstrap/css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/bootstrap/css/bootstrap.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/bootstrap/js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/bootstrap/js/bootstrap.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/daterangepicker
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/daterangepicker/daterangepicker.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/daterangepicker/daterangepicker.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fancytree
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fancytree/jquery.fancytree-all-deps.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fork-awesome
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fork-awesome/css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fork-awesome/css/fork-awesome.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/fork-awesome/css/v5-compat.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/jquery
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/moment
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`
* URL: http://127.0.0.1:8384/vendor/moment/moment.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: CSRF-Token-C4JT7
`

Instances: 81

### Solution



### Reference


* [ http://projects.webappsec.org/Fingerprinting ](http://projects.webappsec.org/Fingerprinting)


#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 45

#### Source ID: 1

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: `password`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: pass
password`
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: `user`
  * Attack: ``
  * Evidence: `user`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user`

Instances: 2

### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.

* URL: http://127.0.0.1:8384/vendor/angular/angular-sanitize.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `FROM`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 5 times, the first in the element starting with: " * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `FROM`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 8 times, the first in the element starting with: " * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `later`
  * Other Info: `The following pattern was used: \bLATER\b and was detected 2 times, the first in the element starting with: "   * namespaces, so they are later accessible via dot notation.", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `TODO`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 3 times, the first in the element starting with: "      currentStrategy = null, // TODO change to either 'sanitize', 'escape' or ['sanitize', 'escapeParameters'] in 3.0.", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `user`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in the element starting with: "   * Tells the module which key must represent the choosed language by a user in the storage.", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/angular/angular-translate.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `where`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 3 times, the first in the element starting with: "   *                                     results that the function returns an object where each key", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bug`
  * Other Info: `The following pattern was used: \bBUG\b and was detected 7 times, the first in the element starting with: "	// We allow this because of a bug in IE8/9 that throws an error", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bugs`
  * Other Info: `The following pattern was used: \bBUGS\b and was detected 4 times, the first in the element starting with: "	// See http://bugs.jquery.com/ticket/13378", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `FROM`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 52 times, the first in the element starting with: " * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `later`
  * Other Info: `The following pattern was used: \bLATER\b and was detected 8 times, the first in the element starting with: "			// IE8 throws error here and will not see later tests", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in the element starting with: "// key/values into a query string", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `select`
  * Other Info: `The following pattern was used: \bSELECT\b and was detected 18 times, the first in the element starting with: "	select,", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `TODO`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 4 times, the first in the element starting with: "							// TODO: identify versions", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `user`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 8 times, the first in the element starting with: "	// Can be adjusted by the user", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `username`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected 2 times, the first in the element starting with: "		username: null,", see evidence field for the suspicious comment/snippet.`
* URL: http://127.0.0.1:8384/vendor/jquery/jquery-2.2.2.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `where`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 8 times, the first in the element starting with: "		// For CommonJS and CommonJS-like environments where a proper `window`", see evidence field for the suspicious comment/snippet.`

Instances: 16

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 200 ](https://cwe.mitre.org/data/definitions/200.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false">
              <span class="fa fa-question-circle"></span>
              <span class="hidden-xs" translate>Help</span>
              <span class="caret"></span>
            </a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`
* URL: http://127.0.0.1:8384/%3Fpassword=ZAP&user=ZAP
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false">
              <span class="fa fa-question-circle"></span>
              <span class="hidden-xs" translate>Help</span>
              <span class="caret"></span>
            </a>`
  * Other Info: `Links have been found that do not have traditional href attributes, which is an indication that this is a modern web application.`

Instances: 2

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://127.0.0.1:8384/rest/debug/support
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: 1

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).   

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `55mRkZJpoxT2G6Fhit9ziatV9jqgDqvm`
  * Other Info: `
cookie:CSRF-Token-C4JT7`
* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `Xax9yJJht33bWSYLxLaGAn4H9so2PZdD`
  * Other Info: `
cookie:CSRF-Token-C4JT7`
* URL: http://127.0.0.1:8384/robots.txt
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `56aUFf3tHbkccxGsjkoY9kZNtbEF4hmm`
  * Other Info: `
cookie:CSRF-Token-C4JT7`
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `gDaCbxVpDDvFukvPkH72NuNKWURUyZwx`
  * Other Info: `
cookie:CSRF-Token-C4JT7`
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: `CSRF-Token-C4JT7`
  * Attack: ``
  * Evidence: `gDaCbxVpDDvFukvPkH72NuNKWURUyZwx`
  * Other Info: `
cookie:CSRF-Token-C4JT7`

Instances: 5

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id)



#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users. 

* URL: http://127.0.0.1:8384/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('advanced/folder-ignoredelete'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%257B%257BdocsURL('intro/gui'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%257B%257BdocsURL(&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/%257B%257BremoteGUIAddress(deviceCfg&29.replace('%2525',%2520'%252525'&29%257D%257D
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/assets/img/favicon-%257B%257BsyncthingStatus(&29%257D%257D.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/assets/img/favicon-default.png
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/assets/img/safari-pinned-tab.svg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://127.0.0.1:8384/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``

Instances: 10

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://127.0.0.1:8384/rest/debug
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``

Instances: 12

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


