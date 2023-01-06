# Azure
## Authentication & Authorization  
I recommend reading the following resources in order:
1. [Azure RBAC documentation | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/)  
2. [What is Azure attribute-based access control (Azure ABAC)? | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview)
3. [Classic subscription administrator roles, Azure roles, and Azure AD roles | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/rbac-and-directory-admin-roles)
4. [Understand Azure role definitions - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
5. [Understand Azure role assignments - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments)
6. [Understand scope for Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
### Best Practices
From [Best practices for Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)  
1. Only grant the access users need  
2. Limit the number of subscription owners  
3. Use Azure AD Privileged Identity Management
4. Assign roles to groups, not users
5. Assign roles using the unique role ID instead of the role name
6. Avoid using a wildcard when creating custom roles
### Notes
####  How Azure RBAC determines if a user has access to a resource [^1]  
1.  A user (or service principal) acquires a token for Azure Resource Manager.
    The token includes the user's group memberships (including transitive group memberships).
2.  The user makes a REST API call to Azure Resource Manager with the token attached.
3.  Azure Resource Manager retrieves all the role assignments and deny assignments that apply to the resource upon which the action is being taken.
4.  If a deny assignment applies, access is blocked. Otherwise, evaluation continues.
5.  Azure Resource Manager narrows the role assignments that apply to this user or their group and determines what roles the user has for this resource.
6.  Azure Resource Manager determines if the action in the API call is included in the roles the user has for this resource. If the roles include `Actions` that have a wildcard (`*`), the effective permissions are computed by subtracting the `NotActions` from the allowed `Actions`. Similarly, the same subtraction is done for any data actions.
    `Actions - NotActions = Effective management permissions`
    `DataActions - NotDataActions = Effective data permissions`
7.  If the user doesn't have a role with the action at the requested scope, access is not allowed. Otherwise, any conditions are evaluated.
8.  If the role assignment includes conditions, they are evaluated. Otherwise access is allowed.
9.  If conditions are met, access is allowed. Otherwise access is not allowed.

The following diagram is a summary of the evaluation logic.
![](/Screenshots/Pasted%20image%2020230106095903.png)
#### Effective roles [^2]
`Actions - NotActions = Effective control plane permissions`
`DataActions - NotDataActions = Effective data plane permissions`

#### Differences between NotActions and deny assignments [^2]

If a user is assigned a role that excludes an action in `NotActions`, and is assigned a second role that grants access to the same action, the user is allowed to perform that action. `NotActions` is not a deny rule – it is simply a convenient way to create a set of allowed actions when specific actions need to be excluded.

#### Role Assignment: Scoping [^3]
> Use the smallest scope that you need to meet your requirements.

For example, if you need to grant a managed identity access to a single storage account, it's good security practice to create the role assignment at the scope of the storage account, not at the resource group or subscription scope.

#### Role Assignment: Principal [^3]
Principals include users, security groups, managed identities, workload identities, and service principals. Principals are created and managed in your Azure Active Directory (Azure AD) tenant. 

When you create a role assignment, you specify the _principal type_. Principal types include _User_, _Group_, and _ServicePrincipal_. It's important to specify the correct principal type. Otherwise, you might get intermittent deployment errors, especially when you work with service principals and managed identities.

#### Role Assignment: Resource deletion behavior [^3]
When you delete a user, group, service principal, or managed identity from Azure AD, it's a good practice to delete any role assignments. They aren't deleted automatically. Any role assignments that refer to a deleted principal ID become invalid.

#### Role Assignment: Conditions [^3]
Some roles support role assignment conditions based on attributes in the context of specific actions. A role assignment condition is an additional check that you can optionally add to your role assignment to provide more fine-grained access control.

For example, you can add a condition that requires an object to have a specific tag for the user to read the object.


---
## Interesting Reads  
[Azure China developer guide | Microsoft Learn](https://learn.microsoft.com/en-us/azure/china/resources-developer-guide)
[Considerations for naming Azure resources - Azure Government | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-concept-naming-resources)
[Azure Government Security - Azure Government | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-plan-security)

[^1]: [Azure RBAC documentation | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
[^2]: [Understand Azure role definitions - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
[^3]: [Understand Azure role assignments - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments)