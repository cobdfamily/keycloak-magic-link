<#ftl output_format="plainText">
<#if name?? && name?has_content>${msg("magiclink-emailGreeting", name)}

</#if>${msg("magiclink-emailBodyTxt", link)}<#if otpCode?? && otpCode?has_content>

${msg("magiclink-emailOtp", otpCode)}</#if>
