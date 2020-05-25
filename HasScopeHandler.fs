open System.Threading.Tasks
open System.Security.Claims

open Microsoft.AspNetCore.Authorization

type HasScopeRequirement(scope, issuer) =
    interface IAuthorizationRequirement
        member val Issuer = issuer with get
        member val Scope = scope with get

/// <summary>This is an f# implementation of an authorization handler found <see href="https://stackoverflow.com/questions/59356354/asp-net-core-web-api-how-can-i-access-httpcontext-in-startup-class/61993846#61993846">here</see>.
/// You can then add this to your services as it is done <see href="https://docs.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased?view=aspnetcore-3.1#code-try-7">in this example</see>.
/// </summary>
type HasScopeHandler() =
    inherit AuthorizationHandler<HasScopeRequirement>()
        override __.HandleRequirementAsync(context, requirement) =
            let scopeClaimFromIssuer = Predicate<Claim>(fun (c: Claim) -> c.Type = "scope" && c.Issuer = requirement.Issuer)
            let userDoesNotHaveScopeClaim = not (context.User.HasClaim(scopeClaimFromIssuer))
            let isRequiredScope s = (s = requirement.Scope)
            let claimOrNull = context.User.FindFirst(scopeClaimFromIssuer)

            if (userDoesNotHaveScopeClaim) then
                Task.CompletedTask
            else
                match claimOrNull with
                | null -> Task.CompletedTask
                | claim ->
                    let scopes = claim.Value.Split(' ')
                    let hasRequiredScope = scopes.Any(fun s -> isRequiredScope s)
                    if (hasRequiredScope) then
                      context.Succeed(requirement)
                      Task.CompletedTask
                    else
                     Task.CompletedTask
