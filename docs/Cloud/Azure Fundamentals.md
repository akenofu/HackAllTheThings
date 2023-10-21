# Azure
## Authentication & Authorization  
I recommend reading the following resources in order:  
1. [What is Azure role-based access control (Azure RBAC)? | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
2. [What is Azure attribute-based access control (Azure ABAC)? | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/conditions-overview)
3. [Classic subscription administrator roles, Azure roles, and Azure AD roles | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/rbac-and-directory-admin-roles)
4. [Understand Azure role definitions - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
5. [Understand Azure role assignments - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments)
6. [Understand scope for Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
7. [Managed identities for Azure resources - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
8. [Apps & service principals in Azure AD - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)
### Best Practices
From [Best practices for Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)  
1. Only grant the access users need  
2. Limit the number of subscription owners  
3. Use Azure AD Privileged Identity Management
4. Assign roles to groups, not users
5. Assign roles using the unique role ID instead of the role name
6. Avoid using a wildcard when creating custom roles
### Notes
####  How Azure RBAC determines if a user has access to a resource[^1]  
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
#### Effective roles[^2]
`Actions - NotActions = Effective control plane permissions`
`DataActions - NotDataActions = Effective data plane permissions`

#### Differences between NotActions and deny assignments[^2]

If a user is assigned a role that excludes an action in `NotActions`, and is assigned a second role that grants access to the same action, the user is allowed to perform that action. `NotActions` is not a deny rule – it is simply a convenient way to create a set of allowed actions when specific actions need to be excluded.

#### Role Assignment: Scoping[^3]
> Use the smallest scope that you need to meet your requirements.

For example, if you need to grant a managed identity access to a single storage account, it's good security practice to create the role assignment at the scope of the storage account, not at the resource group or subscription scope.

#### Role Assignment: Principal[^3]
Principals include users, security groups, managed identities, workload identities, and service principals. Principals are created and managed in your Azure Active Directory (Azure AD) tenant. 

When you create a role assignment, you specify the _principal type_. Principal types include _User_, _Group_, and _ServicePrincipal_. It's important to specify the correct principal type. Otherwise, you might get intermittent deployment errors, especially when you work with service principals and managed identities.

#### Role Assignment: Resource deletion behavior[^3]
When you delete a user, group, service principal, or managed identity from Azure AD, it's a good practice to delete any role assignments. They aren't deleted automatically. Any role assignments that refer to a deleted principal ID become invalid.

#### Role Assignment: Conditions[^3]
Some roles support role assignment conditions based on attributes in the context of specific actions. A role assignment condition is an additional check that you can optionally add to your role assignment to provide more fine-grained access control.

For example, you can add a condition that requires an object to have a specific tag for the user to read the object.

#### Managed identity types [^4]
There are two types of managed identities:
-   **System-assigned**. Some Azure resources, such as virtual machines allow you to enable a managed identity directly on the resource. When you enable a system-assigned managed identity:  
    -   A service principal of a special type is created in Azure AD for the identity. The service principal is tied to the lifecycle of that Azure resource. When the Azure resource is deleted, Azure automatically deletes the service principal for you.
    -   By design, only that Azure resource can use this identity to request tokens from Azure AD.
    -   You authorize the managed identity to have access to one or more services.
-   **User-assigned**. You may also create a managed identity as a standalone Azure resource. You can [create a user-assigned managed identity](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-manage-ua-identity-portal) and assign it to one or more Azure Resources. When you enable a user-assigned managed identity:
    -   A service principal of a special type is created in Azure AD for the identity. The service principal is managed separately from the resources that use it.
    -   User-assigned identities can be used by multiple resources.
    -   You authorize the managed identity to have access to one or more services.

#### Service principal object
To access resources that are secured by an Azure AD tenant, the entity that requires access must be represented by a security principal. This requirement is true for both users (user principal) and applications (service principal). The security principal defines the access policy and permissions for the user/application in the Azure AD tenant. This enables core features such as authentication of the user/application during sign-in, and authorization during resource access.


#### Application objects and service principals [^5]
If you register an application in the portal, an application object and a service principal object are automatically created in your home tenant. If you register/create an application using the Microsoft Graph APIs, creating the service principal object is a separate step.




---
## Interesting Reads  
[Azure China developer guide | Microsoft Learn](https://learn.microsoft.com/en-us/azure/china/resources-developer-guide)
[Considerations for naming Azure resources - Azure Government | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-concept-naming-resources)
[Azure Government Security - Azure Government | Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-plan-security)

[^1]: [Azure RBAC documentation | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
[^2]: [Understand Azure role definitions - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)
[^3]: [Understand Azure role assignments - Azure RBAC | Microsoft Learn](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments)
[^4]: [Managed identities for Azure resources - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
[^5]: [Apps & service principals in Azure AD - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)