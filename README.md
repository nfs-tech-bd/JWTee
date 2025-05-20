# 🔐 JWTee - The Stylish JWT Decoder

[![License](https://img.shields.io/github/license/nfs-tech-bd/jwtee )](https://github.com/nfs-tech-bd/jwtee )
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue )](https://www.python.org/ )
[![PyPI version](https://badge.fury.io/py/jwtee.svg )](https://pypi.org/project/jwtee/ )

> 🔍 Decode JWT tokens like a pro. With JWTee, you get beautiful, colorized output, expiration time detection, and security warnings — all from your terminal.

---

## 🎯 What is JWTee?

**JWTee** (pronounced *"Jot-tee"*) is a powerful and user-friendly command-line tool that decodes JWT tokens into readable JSON format with extra features like:

- ✅ Colorful, styled terminal output
- 🕒 Automatic detection and display of token expiration
- ❌ Warning if token uses insecure `none` algorithm
- 📋 Optional clipboard copy support
- 🛡️ Signature algorithm info (`HS256`, `RS256`, etc.)

Perfect for pentesting, debugging, or just taking a quick peek at those mysterious JWT tokens flying around.

---

## 💻 Installation

### From PyPI (Recommended):

```bash
pip install jwtee
