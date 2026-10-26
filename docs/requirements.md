
# KeyShield AI - System & Software Requirements

This document specifies the software, hardware, system configurations, and permissions needed to develop and run **KeyShield AI**.

---

## 1. Operating System & Subsystems

*   **OS:** Linux (Ubuntu 20.04+, Debian 10+, Fedora 34+, or similar modern distribution).
*   **Kernel Subsystems:**
    *   **`procfs` (`/proc`):** Must be mounted (standard in almost all Linux distributions).
    *   **Input Subsystem (`/dev/input/`):** Character devices (`event*`) must be accessible to monitor physical keystrokes.
    *   **`systemd`:** Recommended to monitor service persistence.

---

## 2. Privileges & Permissions

> [!WARNING]
> By default, Linux restricts access to keyboard input files under `/dev/input/` to the **root** user and members of the **input** group. This is a critical security control to prevent unauthorized programs (like keyloggers) from reading keystrokes.
> 
> To monitor these events, KeyShield AI must run with:
> 1. **Root / Sudo privileges** (e.g., `sudo python3 src/agent.py`), OR
> 2. **Explicit Group Permissions:** The executing user must be added to the `input` group (e.g., `sudo usermod -aG input $USER`).

---

## 3. Programming Environment

*   **Python Version:** Python `3.8` or higher (Python `3.10+` recommended).
*   **System Development Packages:**
    *   `python3-dev` / `python3-devel` (Required if compiling C extensions like `psutil` or `evdev` from source).
    *   `build-essential` (gcc, make, etc.).

---

## 4. Python Package Dependencies

We will declare our dependencies in `requirements.txt`. Here are the primary libraries we will use and why:

| Library | Purpose | Installation Command |
| :--- | :--- | :--- |
| **`psutil`** | Accesses `/proc` to monitor process CPU, memory, PIDs, parents, and connections. | `pip install psutil` |
| **`evdev`** | Interface to the Linux input subsystem (`/dev/input/event*`) to catch raw keystroke events. | `pip install evdev` |
| **`PyYAML`** | Parses configuration files in YAML format (`config/agent.yaml`). | `pip install pyyaml` |
| **`requests`** | Used by Cloud Sync to push logs and threats to our API. | `pip install requests` |
| **`google-genai`** | Official library to interface with Gemini models for AI analysis. | `pip install google-genai` |

---

## 5. Verification Commands

Before writing any agent code, we must verify our environment using the following standard Linux commands:

*   **Check Python Version:**
    ```bash
    python3 --version
    ```
*   **Check pip installation:**
    ```bash
    pip3 --version
    ```
*   **Check `/dev/input` access:**
    ```bash
    ls -l /dev/input/event*
    ```
    *(Verify which user/group owns the event files. Usually owned by root/input)*
