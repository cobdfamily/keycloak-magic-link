<#import "template.ftl" as layout>
<@layout.registrationLayout displayRequiredFields=false displayMessage=false; section>
    <#if section = "form">
        ${msg("magiclink-continuation-wait-for-login")}
    </#if>
    <script>
        setTimeout(() => window.location.reload(), 5000);
    </script>
</@layout.registrationLayout>