# Page snapshot

```yaml
- generic [ref=e2]:
  - generic [ref=e4]:
    - generic [ref=e5]:
      - heading "Provider Admin Portal" [level=1] [ref=e6]
      - paragraph [ref=e7]: Authorized Personnel Only
    - generic [ref=e8]:
      - generic [ref=e9]:
        - generic [ref=e10]: Error
        - paragraph [ref=e11]: Invalid password
      - generic [ref=e12]:
        - generic [ref=e13]:
          - generic [ref=e14]: Security Status
          - generic [ref=e15]: Low Risk
        - generic [ref=e17]:
          - generic [ref=e18]: AAL0
          - generic [ref=e19]: AAL2
        - generic [ref=e22]: password
      - form "Password form" [ref=e23]:
        - generic [ref=e24]:
          - generic [ref=e25]:
            - generic [ref=e26]: Password
            - link "Forgot password?" [ref=e27] [cursor=pointer]:
              - /url: /u/admin/reset-password
          - textbox "Password" [ref=e28]:
            - /placeholder: ••••••••
            - text: password
        - button "Sign In" [ref=e29] [cursor=pointer]
    - generic [ref=e30]:
      - link "Forgot your password?" [ref=e31] [cursor=pointer]:
        - /url: /u/admin/reset-password
      - paragraph [ref=e32]:
        - text: Don't have an account?
        - link "Sign up" [ref=e33] [cursor=pointer]:
          - /url: /u/admin/signup
  - region "Notifications alt+T"
```