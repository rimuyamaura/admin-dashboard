# admin-dashboard

Backend .NET webAPI practice for a user roles management system. Role based authorization using IdentityUser class and JWT authentication.

All registered users can message each other, view own inbox, view own logs. High priority users have permissions to change other user's roles, and can view logs for the entire application.
Unregistered users can register, login, view user's list

Roles and permissions:

|     Role     | Messaging | View all messages | View own logs | View all logs |     Edit other user's roles      |
| :----------: | :-------: | :---------------: | :-----------: | :-----------: | :------------------------------: |
|    OWNER     |    yes    |        yes        |      yes      |      yes      |  can change for all other roles  |
|    ADMIN     |    yes    |        yes        |      yes      |      yes      | can change for manager and below |
|   MANAGER    |    yes    |        no         |      yes      |      no       |                no                |
|     USER     |    yes    |        no         |      yes      |      no       |                no                |
| UNREGISTERED |    no     |        no         |      no       |      no       |                no                |
