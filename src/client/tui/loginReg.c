/**
 * @file loginReg.c
 * @brief
 *
 * @date 2026-06-11
 * @copyright GPLv3 License
 * @section LICENSE
 * PacPlay
 * Copyright (C) 2026 Winston Meursault & Kiraterin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https: //www.gnu.org/licenses/>.
 */

#include "client/auth.h"
#include "client/connection.h"
#include "clientTUI.h"
#include "mainPage.h"
#include "qrcodegen.h"
#include "utils.h"
#include <ctype.h>

#define TUI_LOGIN_GRID_HEIGHT 30
#define TUI_LOGIN_GRID_WIDTH 42
#define TUI_REG_GRID_HEIGHT TUI_LOGIN_GRID_HEIGHT
#define TUI_REG_GRID_WIDTH TUI_LOGIN_GRID_WIDTH
#define TUI_TOTP_RECO_GRID_HEIGHT 10
#define TUI_TOTP_RECO_GRID_WIDTH 50
#define TUI_TOTP_SETUP_GRID_HEIGHT 49
#define TUI_TOTP_SETUP_GRID_WIDTH 100
#define TUI_TOTP_VERIFY_GRID_HEIGHT 20
#define TUI_TOTP_VERIFY_GRID_WIDTH 42
#define TUI_TOTP_ERROR_GRID_HEIGHT 10
#define TUI_TOTP_ERROR_GRID_WIDTH 50

#define PASSWORD_MIN_LEN 6
#define PASSWORD_MAX_LEN 32
#define RESPONSE_BUF_LEN 128
#define QRCODE_PATTERN_LEN 2048

#define QRCODE_VERSION 6

// Login page
ControlPage loginPage;
ControlGrid loginGrid;
ControlLabel loginPrompt;
ControlLabel loginUsernameLabel;
ControlInputBox loginUsernameBox;
ControlLabel loginPasswordLabel;
ControlInputBox loginPasswordBox;
ControlButton loginButton;
ControlLabel loginToRegPrompt;
ControlButton loginToRegButton;
ControlLabel loginStatusLabel;
ControlButton loginExit;

// Register page
ControlPage regPage;
ControlGrid regGrid;
ControlLabel regPrompt;
ControlLabel regUsernameLabel;
ControlInputBox regUsernameBox;
ControlLabel regNicknameLabel;
ControlInputBox regNicknameBox;
ControlLabel regPasswordLabel;
ControlInputBox regPasswordBox;
ControlLabel regConfirmPasswordLabel;
ControlInputBox regConfirmPasswordBox;
ControlButton regButton;
ControlLabel regStatusLabel;
ControlLabel regToLoginPrompt;
ControlButton regToLoginButton;
ControlButton regExit;
bool regSuccess = false;

// TOTP recommend page
ControlPage totpRecommendPage;
ControlGrid totpRecommendGrid;
ControlLabel totpRecommendPrompt;
ControlButton totpRecommendYes;
ControlButton totpRecommendNo;

// TOTP setup page
struct {
    char secret[TOTP_SETUP_SECRET_LEN];
    char *uri;
    size_t uriLen;
    bool totpSucc;
    bool qrSucc;
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(QRCODE_VERSION)];
    uint8_t tmpbuf[qrcodegen_BUFFER_LEN_FOR_VERSION(QRCODE_VERSION)];
    char qrPattern[QRCODE_PATTERN_LEN];
} totpData;
ControlPage totpSetupPage;
ControlGrid totpSetupGrid;
ControlLabel totpSetupPrompt;
ControlLabel totpSetupStatus;
ControlGrid totpSetupQRDisplay;
ControlLabel totpSetupSecret;
ControlButton totpSetupDoneBtn;

// TOTP verify page
ControlPage totpVerifyPage;
ControlGrid totpVerifyGrid;
ControlLabel totpVerifyPrompt;
ControlInputBox totpVerifyBox;
ControlButton totpVerifySubmit;

static void loginRegCleanup() {
    OPENSSL_cleanse(regPasswordBox.buf, INPUTBOX_BUF_MAX_LEN);
    OPENSSL_cleanse(regConfirmPasswordBox.buf, INPUTBOX_BUF_MAX_LEN);
    OPENSSL_cleanse(loginPasswordBox.buf, INPUTBOX_BUF_MAX_LEN);
    loginPasswordBox.curLen = 0;
    loginPasswordBox.curLoc = 0;
    loginPasswordBox.viewBegin = 0;
    regPasswordBox.curLen = 0;
    regPasswordBox.curLoc = 0;
    regPasswordBox.viewBegin = 0;
    regConfirmPasswordBox.curLen = 0;
    regConfirmPasswordBox.curLoc = 0;
    regConfirmPasswordBox.viewBegin = 0;
}

static void loginRegGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_LOGIN_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_LOGIN_GRID_HEIGHT, pViewArea->height);
    self->base.x = MAX(0, pViewArea->width / 2 - TUI_LOGIN_GRID_WIDTH / 2);
    self->base.y = MAX(0, pViewArea->height / 2 - TUI_LOGIN_GRID_HEIGHT / 2);
    clear();
}

static void loginBtnOnClick(ControlButton *self) {
    (void)self;

    tuiAppVisibilityChange((Control *)&loginStatusLabel, true);
    char username[LOGIN_USERNAME_LEN] = {0};
    char nickname[LOGIN_NICKNAME_LEN] = {0};
    char password[PASSWORD_MAX_LEN] = {0};
    char response[RESPONSE_BUF_LEN] = {0};
    bool totpEnabled;
    bool totpRequest;
    if (loginUsernameBox.curLen >= LOGIN_USERNAME_LEN) {
        strcpy(loginStatusLabel.text, "Username too long");
        return;
    }
    if (loginPasswordBox.curLen >= PASSWORD_MAX_LEN) {
        strcpy(loginStatusLabel.text, "Password too long");
        return;
    }
    memcpy(username, loginUsernameBox.buf, loginUsernameBox.curLen);
    username[loginUsernameBox.curLen] = '\0';
    memcpy(password, loginPasswordBox.buf, loginPasswordBox.curLen);
    password[loginPasswordBox.curLen] = '\0';
    int result = clientLogin(client, username, password, response, &totpEnabled,
                             &totpRequest, nickname);
    OPENSSL_cleanse(password, sizeof(password));
    loginRegCleanup();
    if (result == CLIENT_FAIL) {
        if (strlen(response) <= (size_t)loginStatusLabel.base.width) {
            strcpy(loginStatusLabel.text, response);
        } else {
            strcpy(loginStatusLabel.text, "Error when logining");
        }
    } else {
        homePageInitUpdate(nickname, username);
        if (!totpEnabled) {
            tuiAppChangePage(&totpRecommendPage);
            return;
        }
        if (totpRequest) {
            tuiAppChangePage(&totpVerifyPage);
        } else {
            tuiAppChangePage(&homePage);
        }
    }
}

static void loginToRegBtnOnClick(ControlButton *self) {
    (void)self;
    tuiAppChangePage(&regPage);
    loginRegCleanup();
}

static bool regInputCheck() {
    if (regUsernameBox.curLen == 0) {
        strcpy(regStatusLabel.text, "Username cannot be empty");
        return false;
    }
    if (regUsernameBox.curLen >= LOGIN_USERNAME_LEN) {
        sprintf(regStatusLabel.text, "Username too long (%zu > %d)",
                regUsernameBox.curLen, LOGIN_USERNAME_LEN - 1);
        return false;
    }
    if (regNicknameBox.curLen == 0) {
        strcpy(regStatusLabel.text, "Nickname cannot be empty");
        return false;
    }
    if (regNicknameBox.curLen >= LOGIN_USERNAME_LEN) {
        sprintf(regStatusLabel.text, "Nickname too long (%zu > %d)",
                regNicknameBox.curLen, LOGIN_USERNAME_LEN - 1);
        return false;
    }
    if (regPasswordBox.curLen < PASSWORD_MIN_LEN) {
        sprintf(regStatusLabel.text, "Password too short (%zu < %d)",
                regPasswordBox.curLen, PASSWORD_MIN_LEN);
        return false;
    }
    if (regPasswordBox.curLen >= PASSWORD_MAX_LEN) {
        sprintf(regStatusLabel.text, "Password too long (%zu > %d)",
                regPasswordBox.curLen, PASSWORD_MAX_LEN - 1);
        return false;
    }

    struct {
        bool hasDigit;
        bool hasLetter;
    } require = {false, false};
    for (size_t i = 0; i < regPasswordBox.curLen; ++i) {
        char cur = regPasswordBox.buf[i];
        if (isdigit(cur)) {
            require.hasDigit = true;
        }
        if (isalpha(cur)) {
            require.hasLetter = true;
        }
    }
    if (!require.hasDigit) {
        strcpy(regStatusLabel.text, "Password must contain a digit");
        return false;
    }
    if (!require.hasLetter) {
        strcpy(regStatusLabel.text, "Password must contain a letter");
        return false;
    }

    if (regPasswordBox.curLen != regConfirmPasswordBox.curLen ||
        strncmp(regPasswordBox.buf, regConfirmPasswordBox.buf,
                regPasswordBox.curLen) != 0) {
        strcpy(regStatusLabel.text, "Confirm password does not match");
        return false;
    }

    return true;
}

static void regBtnOnClick(ControlButton *self) {
    (void)self;
    tuiAppVisibilityChange((Control *)&regStatusLabel, true);
    if (regSuccess) {
        return;
    }
    if (regInputCheck()) {
        char username[LOGIN_USERNAME_LEN] = {0};
        char nickname[LOGIN_NICKNAME_LEN] = {0};
        char password[PASSWORD_MAX_LEN] = {0};
        char response[RESPONSE_BUF_LEN] = {0};
        strncpy(username, regUsernameBox.buf, regUsernameBox.curLen);
        strncpy(nickname, regNicknameBox.buf, regNicknameBox.curLen);
        strncpy(password, regPasswordBox.buf, regPasswordBox.curLen);
        int result =
            clientRegister(client, username, nickname, password, response);
        OPENSSL_cleanse(username, sizeof(username));
        OPENSSL_cleanse(password, sizeof(password));
        loginRegCleanup();
        if (result == CLIENT_FAIL) {
            if (strlen(response) <= (size_t)regStatusLabel.base.width &&
                strlen(response) > 0) {
                strcpy(regStatusLabel.text, response);
            } else {
                strcpy(regStatusLabel.text, "Error when registering");
            }
        } else {
            regSuccess = true;
            strcpy(regStatusLabel.text, response);
        }
    }
}

static void regToLoginBtnOnClick(ControlButton *self) {
    (void)self;
    regSuccess = false;
    tuiAppChangePage(&loginPage);
    loginRegCleanup();
}

static void loginRegStatusDraw(ControlLabel *self) {
    (void)self;
    werase(self->base.windowHandler);
    if (self->text != NULL) {
        if (regSuccess) {
            wattron(self->base.windowHandler, COLOR_PAIR(ColorAttrGreen));
            mvwprintw(self->base.windowHandler, 0, 0, "%s", self->text);
            wattroff(self->base.windowHandler, COLOR_PAIR(ColorAttrGreen));
        } else {
            wattron(self->base.windowHandler, COLOR_PAIR(ColorAttrRed));
            mvwprintw(self->base.windowHandler, 0, 0, "%s", self->text);
            wattroff(self->base.windowHandler, COLOR_PAIR(ColorAttrRed));
        }
    }
    wnoutrefresh(self->base.windowHandler);
}

static void exitBtn(ControlButton *self) {
    (void)self;
    loginRegCleanup();
    clientDisconnect(client);
    tuiAppChangePage(&connectPage);
}

static void totpSetup() {
    char response[RESPONSE_BUF_LEN];
    bool uriSucc;
    bool qrSucc = false;
    bool res = clientTOTPSetup(client, response, totpData.secret, &totpData.uri,
                               &uriSucc, &totpData.uriLen);
    if (res == CLIENT_SUCC) {
        if (uriSucc) {
            qrSucc = qrcodegen_encodeText(
                totpData.uri, totpData.tmpbuf, totpData.qr, qrcodegen_Ecc_LOW,
                QRCODE_VERSION, QRCODE_VERSION, qrcodegen_Mask_AUTO, true);
        }
        totpData.totpSucc = true;
        totpData.qrSucc = uriSucc && qrSucc;
    } else {
        strcpy(totpSetupStatus.text, response);
        totpData.totpSucc = false;
    }
}

static void totpGenQRPattern() {
    int size = qrcodegen_getSize(totpData.qr);
    size_t offset = 0;
    totpData.qrPattern[0] = '\0';
    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            bool isBlack = qrcodegen_getModule(totpData.qr, x, y);
            if (offset + 1 < QRCODE_PATTERN_LEN - 2) {
                totpData.qrPattern[offset] = isBlack ? '1' : '0';
                offset++;
            }
        }
        if (offset + 1 < QRCODE_PATTERN_LEN - 1) {
            totpData.qrPattern[offset] = '\n';
            offset++;
        }
    }
    totpData.qrPattern[offset] = '\0';
}

static void totpRecommendGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_TOTP_RECO_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_TOTP_RECO_GRID_HEIGHT, pViewArea->height);
    self->base.x = MAX(0, pViewArea->width / 2 - TUI_TOTP_RECO_GRID_WIDTH / 2);
    self->base.y =
        MAX(0, pViewArea->height / 2 - TUI_TOTP_RECO_GRID_HEIGHT / 2);
    clear();
}

static void totpRecommendYesBtnOnClick(ControlButton *self) {
    (void)self;
    tuiAppChangePage(&totpSetupPage);
    totpSetup();
    if (!totpData.totpSucc) {
        tuiAppVisibilityChange((Control *)&totpSetupQRDisplay, false);
    } else if (!totpData.qrSucc) {
        strcpy(totpSetupStatus.text, "Please input below secret manually:");
        strcpy(totpSetupSecret.text, totpData.secret);
    } else {
        totpGenQRPattern();
        OPENSSL_cleanse(totpData.qr, sizeof(totpData.qr));
        OPENSSL_cleanse(totpData.tmpbuf, sizeof(totpData.tmpbuf));
        OPENSSL_cleanse(totpData.uri, totpData.uriLen);
        free(totpData.uri);
        totpData.uri = NULL;
    }
}

static void totpRecommendNoBtnOnClick(ControlButton *self) {
    (void)self;
    tuiAppChangePage(&homePage);
}

static void totpSetupGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_TOTP_SETUP_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_TOTP_SETUP_GRID_HEIGHT, pViewArea->height);
    self->base.x = MAX(0, pViewArea->width / 2 - TUI_TOTP_SETUP_GRID_WIDTH / 2);
    self->base.y =
        MAX(0, pViewArea->height / 2 - TUI_TOTP_SETUP_GRID_HEIGHT / 2);
    if (totpData.totpSucc && totpData.qrSucc) {
        if ((pViewArea->width < TUI_TOTP_SETUP_GRID_WIDTH ||
             pViewArea->height < TUI_TOTP_SETUP_GRID_HEIGHT)) {
            tuiAppVisibilityChange((Control *)&totpSetupQRDisplay, false);
            tuiAppVisibilityChange((Control *)&totpSetupStatus, true);
            strcpy(totpSetupSecret.text, totpData.secret);
            strcpy(totpSetupPrompt.text,
                   "Input secret manually or enlarge the window");
            tuiAppVisibilityChange((Control *)&totpSetupSecret, true);
        } else {
            strcpy(totpSetupPrompt.text, "Scan with your authenticator app");
            tuiAppVisibilityChange((Control *)&totpSetupQRDisplay, true);
            tuiAppVisibilityChange((Control *)&totpSetupStatus, false);
            tuiAppVisibilityChange((Control *)&totpSetupSecret, false);
        }
    }
    clear();
}

static void totpSetupQRDisplayDraw(ControlGrid *self) {
    werase(self->base.windowHandler);
    int size = 0;
    const char *scanPtr = totpData.qrPattern;
    while (*scanPtr != '\0' && *scanPtr != '\n') {
        size++;
        scanPtr++;
    }
    int currentY = 0;
    int currentX = 0;
    WINDOW *win = self->base.windowHandler;
    wattron(win, COLOR_PAIR(ColorAttrStableWhite));
    for (int i = 0; i < (size * 2 + 4); i++) {
        mvwaddch(win, currentY, currentX + i, ' ');
    }
    currentY++;
    const char *p = totpData.qrPattern;
    mvwaddstr(win, currentY, currentX, "  ");
    currentX += 2;
    while (*p != '\0') {
        if (*p == '\n') {
            wattron(win, COLOR_PAIR(ColorAttrStableWhite));
            waddstr(win, "  ");
            currentY++;
            currentX = 0;
            if (*(p + 1) != '\0') {
                mvwaddstr(win, currentY, currentX, "  ");
                currentX += 2;
            }
        } else if (*p == '1') {
            wattron(win, COLOR_PAIR(ColorAttrStableBlack));
            waddstr(win, "  ");
        } else if (*p == '0') {
            wattron(win, COLOR_PAIR(ColorAttrStableWhite));
            waddstr(win, "  ");
        }
        p++;
    }
    wattron(win, COLOR_PAIR(ColorAttrStableWhite));
    for (int i = 0; i < (size * 2 + 4); i++) {
        mvwaddch(win, currentY, currentX + i, ' ');
    }
    wattroff(win, COLOR_PAIR(ColorAttrStableBlack));
    wattroff(win, COLOR_PAIR(ColorAttrStableWhite));
    wattrset(win, A_NORMAL);
    wnoutrefresh(self->base.windowHandler);
}

static void totpSetupPromptResize(ControlLabel *self) {
    self->base.x = totpSetupGrid.base.width / 2 - strlen(self->text) / 2;
}

static void totpSetupSecretResize(ControlLabel *self) {
    self->base.x = totpSetupGrid.base.width / 2 - strlen(self->text) / 2;
    self->base.y = totpSetupGrid.base.height / 2;
}

static void totpSetupDoneBtnOnClick(ControlButton *self) {
    (void)self;
    OPENSSL_cleanse(totpSetupSecret.text, sizeof(TOTP_SETUP_SECRET_LEN));
    OPENSSL_cleanse(totpData.secret, sizeof(totpData.secret));
    tuiAppChangePage(&totpVerifyPage);
}

static void totpVerifyGridResize(ControlGrid *self) {
    self->base.width = MIN(TUI_TOTP_VERIFY_GRID_WIDTH, pViewArea->width);
    self->base.height = MIN(TUI_TOTP_VERIFY_GRID_HEIGHT, pViewArea->height);
    self->base.x =
        MAX(0, pViewArea->width / 2 - TUI_TOTP_VERIFY_GRID_WIDTH / 2);
    self->base.y =
        MAX(0, pViewArea->height / 2 - TUI_TOTP_VERIFY_GRID_HEIGHT / 2);
    clear();
}

static void totpVerifyBtnOnClick(ControlButton *self) {
    (void)self;
    char code[7] = {0};
    char nickname[LOGIN_NICKNAME_LEN] = {0};
    char response[RESPONSE_BUF_LEN] = {0};
    strncpy(code, totpVerifyBox.buf, MIN(totpVerifyBox.curLen, 6));
    bool res = clientTOTPVerify(client, code, response, nickname);
    if (res != CLIENT_SUCC) {
        strcpy(loginStatusLabel.text, response);
        tuiAppVisibilityChange((Control *)&loginStatusLabel, true);
        tuiAppChangePage(&loginPage);
    } else {
        homePageInitUpdate(nickname, NULL);
        tuiAppChangePage(&homePage);
    }
}

void tuiClientLoginRegInit() {
    // login page

    controlPageConstruct(&loginPage);
    controlGridConstruct(&loginGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         loginRegGridResize, NULL, NULL, NULL);
    controlLabelConstruct(&loginPrompt, "Login", 0, 2, 2, NULL, NULL, NULL,
                          NULL);
    controlLabelConstruct(&loginUsernameLabel, "Username: ", 0, 6, 3, NULL,
                          NULL, NULL, NULL);
    controlInputBoxConstruct(&loginUsernameBox, 20, 5, 15, false, NULL, NULL,
                             NULL, NULL, NULL);
    controlLabelConstruct(&loginPasswordLabel, "Password: ", 0, 9, 3, NULL,
                          NULL, NULL, NULL);
    controlInputBoxConstruct(&loginPasswordBox, 20, 8, 15, true, NULL, NULL,
                             NULL, NULL, NULL);
    controlButtonConstruct(&loginButton, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_LOGIN_GRID_HEIGHT - 2 * TUI_BTN_HEIGHT - 1,
                           TUI_LOGIN_GRID_WIDTH - TUI_BTN_WIDTH - 2, "Login",
                           NULL, loginBtnOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&loginToRegPrompt, "I have no account: ", 0,
                          TUI_LOGIN_GRID_HEIGHT - 3, 3, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&loginToRegButton, TUI_BTN_HEIGHT, 18,
                           TUI_LOGIN_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_LOGIN_GRID_WIDTH - 18 - 2, "To register...",
                           NULL, loginToRegBtnOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&loginExit, TUI_BTN_HEIGHT, 6, 1,
                           TUI_LOGIN_GRID_WIDTH - 6 - 2, "Exit", NULL, exitBtn,
                           NULL, NULL, NULL);
    controlLabelConstruct(&loginStatusLabel, "", TUI_LOGIN_GRID_WIDTH - 6,
                          TUI_LOGIN_GRID_HEIGHT - 2 * TUI_BTN_HEIGHT - 3, 3,
                          loginRegStatusDraw, NULL, NULL, NULL);
    tuiAppVisibilityChange((Control *)&loginStatusLabel, false);

    tuiAppControlRegister((Control *)&loginPage, NULL);
    tuiAppControlRegister((Control *)&loginGrid, (Control *)&loginPage);
    tuiAppControlRegister((Control *)&loginPrompt, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginUsernameLabel,
                          (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginUsernameBox, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginPasswordLabel,
                          (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginPasswordBox, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginButton, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginToRegPrompt, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginToRegButton, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginExit, (Control *)&loginGrid);
    tuiAppControlRegister((Control *)&loginStatusLabel, (Control *)&loginGrid);

    // register page

    controlPageConstruct(&regPage);
    controlGridConstruct(&regGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         loginRegGridResize, NULL, NULL, NULL);
    controlLabelConstruct(&regPrompt, "Register", 0, 2, 2, NULL, NULL, NULL,
                          NULL);
    controlLabelConstruct(&regUsernameLabel, "Username: ", 0, 6, 3, NULL, NULL,
                          NULL, NULL);
    controlInputBoxConstruct(&regUsernameBox, 20, 5, 15, false, NULL, NULL,
                             NULL, NULL, NULL);
    controlLabelConstruct(&regNicknameLabel, "Nickname: ", 0, 9, 3, NULL, NULL,
                          NULL, NULL);
    controlInputBoxConstruct(&regNicknameBox, 20, 8, 15, false, NULL, NULL,
                             NULL, NULL, NULL);
    controlLabelConstruct(&regPasswordLabel, "Password: ", 0, 12, 3, NULL, NULL,
                          NULL, NULL);
    controlInputBoxConstruct(&regPasswordBox, 20, 11, 15, true, NULL, NULL,
                             NULL, NULL, NULL);
    controlLabelConstruct(&regConfirmPasswordLabel,
                          "Confirm your password: ", 0, 15, 3, NULL, NULL, NULL,
                          NULL);
    controlInputBoxConstruct(&regConfirmPasswordBox, 20, 16, 15, true, NULL,
                             NULL, NULL, NULL, NULL);
    controlButtonConstruct(&regButton, TUI_BTN_HEIGHT, TUI_BTN_WIDTH + 1,
                           TUI_LOGIN_GRID_HEIGHT - 2 * TUI_BTN_HEIGHT - 1,
                           TUI_LOGIN_GRID_WIDTH - (TUI_BTN_WIDTH + 1) - 2,
                           "Register", NULL, regBtnOnClick, NULL, NULL, NULL);
    controlLabelConstruct(&regToLoginPrompt, "I have an account: ", 0,
                          TUI_LOGIN_GRID_HEIGHT - 3, 3, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&regToLoginButton, TUI_BTN_HEIGHT, 18,
                           TUI_LOGIN_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_LOGIN_GRID_WIDTH - 18 - 2, "To login...", NULL,
                           regToLoginBtnOnClick, NULL, NULL, NULL);
    controlButtonConstruct(&regExit, TUI_BTN_HEIGHT, 6, 1,
                           TUI_LOGIN_GRID_WIDTH - 6 - 2, "Exit", NULL, exitBtn,
                           NULL, NULL, NULL);
    controlLabelConstruct(&regStatusLabel, "", TUI_LOGIN_GRID_WIDTH - 6,
                          TUI_LOGIN_GRID_HEIGHT - 2 * TUI_BTN_HEIGHT - 3, 3,
                          loginRegStatusDraw, NULL, NULL, NULL);
    tuiAppVisibilityChange((Control *)&regStatusLabel, false);

    tuiAppControlRegister((Control *)&regPage, NULL);
    tuiAppControlRegister((Control *)&regGrid, (Control *)&regPage);
    tuiAppControlRegister((Control *)&regPrompt, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regUsernameLabel, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regUsernameBox, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regNicknameLabel, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regNicknameBox, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regPasswordLabel, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regPasswordBox, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regConfirmPasswordLabel,
                          (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regConfirmPasswordBox,
                          (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regButton, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regToLoginPrompt, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regToLoginButton, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regExit, (Control *)&regGrid);
    tuiAppControlRegister((Control *)&regStatusLabel, (Control *)&regGrid);

    // TOTP recommend Page

    controlPageConstruct(&totpRecommendPage);
    controlGridConstruct(&totpRecommendGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         totpRecommendGridResize, NULL, NULL, NULL);
    controlLabelConstruct(&totpRecommendPrompt,
                          "Enable TOTP for stronger account protection?", 0, 3,
                          3, NULL, NULL, NULL, NULL);
    controlButtonConstruct(&totpRecommendYes, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_TOTP_RECO_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_TOTP_RECO_GRID_WIDTH - 2 * TUI_BTN_WIDTH - 3,
                           "Yes", NULL, totpRecommendYesBtnOnClick, NULL, NULL,
                           NULL);
    controlButtonConstruct(&totpRecommendNo, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_TOTP_RECO_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_TOTP_RECO_GRID_WIDTH - TUI_BTN_WIDTH - 2, "No",
                           NULL, totpRecommendNoBtnOnClick, NULL, NULL, NULL);

    tuiAppControlRegister((Control *)&totpRecommendPage, NULL);
    tuiAppControlRegister((Control *)&totpRecommendGrid,
                          (Control *)&totpRecommendPage);
    tuiAppControlRegister((Control *)&totpRecommendPrompt,
                          (Control *)&totpRecommendGrid);
    tuiAppControlRegister((Control *)&totpRecommendYes,
                          (Control *)&totpRecommendGrid);
    tuiAppControlRegister((Control *)&totpRecommendNo,
                          (Control *)&totpRecommendGrid);

    // TOTP setup page
    controlPageConstruct(&totpSetupPage);
    controlGridConstruct(&totpSetupGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         totpSetupGridResize, NULL, NULL, NULL);
    controlLabelConstruct(&totpSetupPrompt, "Scan with your authenticator app",
                          45, 1, TUI_TOTP_SETUP_GRID_WIDTH / 2 - 16, NULL,
                          totpSetupPromptResize, NULL, NULL);
    controlLabelConstruct(&totpSetupStatus, "", TUI_TOTP_SETUP_GRID_WIDTH - 3,
                          3, 2, loginRegStatusDraw, NULL, NULL, NULL);
    controlGridConstruct(&totpSetupQRDisplay, 43, 86, 2,
                         TUI_TOTP_SETUP_GRID_WIDTH / 2 - 43, LayoutNone, 0, 0,
                         totpSetupQRDisplayDraw, NULL, NULL, NULL, NULL);
    controlLabelConstruct(
        &totpSetupSecret, "", TOTP_SETUP_SECRET_LEN, 2,
        TUI_TOTP_SETUP_GRID_WIDTH / 2 - TOTP_SETUP_SECRET_LEN / 2,
        loginRegStatusDraw, totpSetupSecretResize, NULL, NULL);
    tuiAppVisibilityChange((Control *)&totpSetupSecret, false);
    controlButtonConstruct(&totpSetupDoneBtn, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_TOTP_SETUP_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_TOTP_SETUP_GRID_WIDTH / 2 - TUI_BTN_WIDTH / 2,
                           "Done", NULL, totpSetupDoneBtnOnClick, NULL, NULL,
                           NULL);

    tuiAppControlRegister((Control *)&totpSetupPage, NULL);
    tuiAppControlRegister((Control *)&totpSetupGrid, (Control *)&totpSetupPage);
    tuiAppControlRegister((Control *)&totpSetupPrompt,
                          (Control *)&totpSetupGrid);
    tuiAppControlRegister((Control *)&totpSetupStatus,
                          (Control *)&totpSetupGrid);
    tuiAppControlRegister((Control *)&totpSetupQRDisplay,
                          (Control *)&totpSetupGrid);
    tuiAppControlRegister((Control *)&totpSetupSecret,
                          (Control *)&totpSetupGrid);
    tuiAppControlRegister((Control *)&totpSetupDoneBtn,
                          (Control *)&totpSetupGrid);

    // TOTP verify page
    controlPageConstruct(&totpVerifyPage);
    controlGridConstruct(&totpVerifyGrid, 0, 0, 0, 0, LayoutNone, 0, 0, NULL,
                         totpVerifyGridResize, NULL, NULL, NULL);
    controlInputBoxConstruct(&totpVerifyBox, 20, 10,
                             TUI_TOTP_VERIFY_GRID_WIDTH / 2 - 10, false, NULL,
                             NULL, NULL, NULL, NULL);
    controlLabelConstruct(&totpVerifyPrompt, "Please input TOTP code:", 0, 3, 3,
                          NULL, NULL, NULL, NULL);
    controlButtonConstruct(&totpVerifySubmit, TUI_BTN_HEIGHT, TUI_BTN_WIDTH,
                           TUI_TOTP_VERIFY_GRID_HEIGHT - TUI_BTN_HEIGHT - 1,
                           TUI_TOTP_VERIFY_GRID_WIDTH - 2 * TUI_BTN_WIDTH - 3,
                           "Verify", NULL, totpVerifyBtnOnClick, NULL, NULL,
                           NULL);

    tuiAppControlRegister((Control *)&totpVerifyPage, NULL);
    tuiAppControlRegister((Control *)&totpVerifyGrid,
                          (Control *)&totpVerifyPage);
    tuiAppControlRegister((Control *)&totpVerifyPrompt,
                          (Control *)&totpVerifyGrid);
    tuiAppControlRegister((Control *)&totpVerifyBox,
                          (Control *)&totpVerifyGrid);
    tuiAppControlRegister((Control *)&totpVerifySubmit,
                          (Control *)&totpVerifyGrid);
}
