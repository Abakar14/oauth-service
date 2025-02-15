# Open futures for Oauth2 Authentication service
## TODO

### Open
- [ ] Implement Other OAuth2 Flows
  If you need more than client_credentials, implement:
    - authorization_code for user-based flows.
    - password (resource owner) flow if you need it. 
    - refresh_token to allow clients to refresh tokens.
- [ ] Handle Token Expiration Automatically
    - Implement token refresh logic in your client applications (Angular frontend, Postman, etc.) 
      so tokens are renewed without manual intervention.
- [ ] Add Scopes and Authorities 
  - Define roles (e.g., ROLE_ADMIN, ROLE_USER).
  - Assign them to your RegisteredClient.
  - Secure your API methods based on roles and scopes.
- [ ] Add More Clients : Register more clients if you have multiple services or frontends.
- [ ] Centralized Logging and Monitoring
     - Since you want to implement the ELK stack, make sure to:
       1- Log all authentication attempts.
       2- Track token usage.
       3- Monitor your OAuth server for unusual activity.
-[ ] Clean Up and Refactor
     - Move sensitive configurations like client_secret to your application.yml.
     - Ensure secrets are environment-specific and not hardcoded.
- [ ] Documentation
     - Document all endpoints.
     - Explain how to obtain and use tokens.
     - List all registered clients and their permissions.
### In Progress
- [ ] update Readme.md


### Done ✓
- [x] build ouath2 authentication-server
- [x] Oauth2 worked  
  - curl -X POST -u client:secret -d "grant_type=client_credentials" http://localhost:8082/oauth2/token
    { 
        "access_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjbGllbnQiLCJhdWQiOiJjbGllbnQiLCJuYmYiOjE3Mzk2MjIwMjgsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MiIsImV4cCI6MTczOTYyMjMyOCwiaWF0IjoxNzM5NjIyMDI4LCJqdGkiOiJjZjI0NzFmYy00MzQ3LTQ1NTItYTk2Ni1iNjRlMTJiY2Y4YTMifQ.EIHN6FhDG_6dw5J_8ATLWnr-aDLU2f0qx5LKAQWmwwTZmh8vLXYnVfA4zaO--aos2cHhrWNHWcQ_sjxibU7X4R35fnP5y671taZzN1g1pDdKZJ-QTy4HuLZg8SkzhRDqxU7wLQGD1GzKaV7Pln7g7rc-T0BPi_tTAeim2yBvidw79cCMMQFBi_PgWx03cr7Rz2VpGgmPGY_6TIpGuyShadPwV4xAPAmyI0fVL4pB48dGQvnZdohDKyStmSfH7y9YQhXjnBuPbNC84xAbeCSDXm4kJX3qrMx7sdxHz58efa6cGFSK2cwSO7NnQUcZM21uUpK_3d7gDHCaodNilNBCKA",
        "token_type":"Bearer",
        "expires_in":299
  } 


