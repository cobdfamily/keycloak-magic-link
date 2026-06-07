<#ftl output_format="HTML">
<html>
<body>
<#if name?? && name?has_content><p>${msg("magiclink-emailGreeting", name)}</p></#if>
${msg("magiclink-emailBodyHtml", link)?no_esc}
<#if otpCode?? && otpCode?has_content><p>${msg("magiclink-emailOtp", otpCode)}</p></#if>
</body>
</html>
