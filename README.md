# go-auth0
go-auth0

    curl --location 'localhost:5100/oauth_credential' \
    --header 'Content-Type: application/json' \
    --data '{
        "user":"admin",
        "password":"admin"
    }'


    curl --location 'localhost:5100/refresh_token' \
    --header 'Content-Type: application/json' \
    --data '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJsYW1iZGEtZ28tYXV0ZW50aWNhdGlvbiIsInZlcnNpb24iOiIyIiwiand0X2lkIjoiYzE1YmE4MGItZDE2MS00OWM4LTkwM2MtMjdhZDMzNmQxMjkwIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTczMzY3MDMxM30.4nYpMemdZYQfhe4hfFTEHM-EdeLsQoCiKXJnQNMy9js"
    }'

    curl --location 'localhost:5100/wellKnown/1'

    curl --location 'localhost:5100/tokenValidationRSA/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJsYW1iZGEtZ28tYXV0ZW50aWNhdGlvbiIsInZlcnNpb24iOiIyIiwiand0X2lkIjoiODYwYjNkOGYtODk3MC00ODE0LTk0MTAtOWY4NzFiMjc3NDFiIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTczMzY2NDg1NH0.S9bfRHmsw9kA7LSNQg4X5ovCCkoAhrZnQuOIJzrk3AXtYIW0cNO0QJB5a7kXlGkl5cuWo4iS5xv1Fw0h4gsX5PnuYdrPxQZMdSAsmSgCsxS5Lrtt-YxpikGi-f0O_RbRoWc4y39-x6lg6gbnowTTYXFeQb1U4qwYb-PRl9fSammAlW2KUGzwcM1SqrDJ820thgUUqkPFgUWsd-aPQDCs_W7-VfiMKIojcqUgDn3o2kF3bCFMYTmcTHs69e18UEPORhi_F0ThIDGg9GWPRrTyLyRUO_8pesphsWtH6HB3-IRxY2HBWH3O_xIKf0mmSnhPZycwJLUTlVvgn8_j4l4tTg'