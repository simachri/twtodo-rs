# Microsoft To-Do integration with Taskwarrior written in Rust

  - [ ] Add mechanism to provide configuration.
    - Client secret
    - Other

## Install

  1. Register an application on _Microsoft Azure_:
     - Supported account types: _Accounts in any organizational directory (Any Azure AD 
       directory - Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)_
     - Under _Authentication_, add a _Single Page Application_ with _Redirect URI_
       `http://localhost:23456/redirect`.
     - Under _Certificate & secrets_, add a _Client secret_
     - Under _API permissions_, add `Tasks.Read`.

  1. Add the _Client secret_ to a file `.env` in the project root directory.



