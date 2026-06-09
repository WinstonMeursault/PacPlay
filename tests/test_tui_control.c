/**
 * @file test_tui_control.c
 * @brief Unit tests for TUI control construction, vtable correctness, and
 * InputBox text manipulation logic.
 *
 * All tests run without ncurses terminal — they verify data structure
 * integrity, field initialisation, and buffer manipulation only.
 *
 * @date 2026-06-08
 * @copyright GPLv3 License
 */

#include "tui/control.h"
#include "tui/tuimsg.h"
#include "test_utils.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ────────────────────────── test-local constants ────────────────────────── */

enum {
    TestWidth = 20,
    TestHeight = 3,
    TestX = 2,
    TestY = 1,
    TestHmargin = 1,
    TestVmargin = 1,
    DefaultIndex = 0,
    Zero = 0,
    One = 1,
    Two = 2,
    Three = 3,
    BufSmall = 5,
    LabelMax = 128,
    BtnMax = 20,
    InputMax = 128,
    IntZero = 0,
    IntOne = 1,
    IntTwo = 2,
    OverMax = 130,
    MinWidth = 3,
    SmallWidth = 1,
    DelChar = 0x7F
};

static int gClickCount = 0;

/* ────────────────────────── stub callbacks ──────────────────────────────── */

static void dummyOnClick(ControlButton *self) {
    (void)self;
    gClickCount++;
}

static void dummyOnSubmit(ControlInputBox *self) {
    (void)self;
    gClickCount++;
}

static void dummyCbBtn(ControlButton *self) { (void)self; }
static void dummyCbGrid(ControlGrid *self) { (void)self; }
static void dummyCbLabel(ControlLabel *self) { (void)self; }
static void dummyCbInputBox(ControlInputBox *self) { (void)self; }

/* ────────────────── ControlPage tests ───────────────────────────────────── */

static void testControlPageConstruct(void) {
    ControlPage page;
    memset(&page, 0, sizeof(page));
    controlPageConstruct(&page);

    ASSERT_TRUE(page.isPage);
    ASSERT_TRUE(page.isContainer);
    ASSERT_FALSE(page.focusable);
    ASSERT_FALSE(page.focused);
    ASSERT_FALSE(page.takeOverInput);
    /* Page starts visible — page visibility is managed at page-switch time. */
    ASSERT_TRUE(page.visible);
    ASSERT_UINT_EQ(page.index, DefaultIndex);
    ASSERT_UINT_EQ(page.childCount, DefaultIndex);
    ASSERT_NOT_NULL(page.vtable.msgHandler);
    ASSERT_NULL(page.vtable.draw);
    ASSERT_NULL(page.windowHandler);
}

/* ────────────────── ControlButton tests ─────────────────────────────────── */

static void testControlButtonConstruct(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));
    gClickCount = 0;

    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, "OK",
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn);

    ASSERT_TRUE(btn.base.focusable);
    ASSERT_FALSE(btn.base.isContainer);
    ASSERT_FALSE(btn.base.focused);
    ASSERT_FALSE(btn.base.isPage);
    ASSERT_FALSE(btn.base.takeOverInput);
    ASSERT_TRUE(btn.base.visible);
    ASSERT_INT_EQ(btn.base.height, TestHeight);
    ASSERT_INT_EQ(btn.base.width, TestWidth);
    ASSERT_INT_EQ(btn.base.y, TestY);
    ASSERT_INT_EQ(btn.base.x, TestX);
    ASSERT_NOT_NULL(btn.text);
    ASSERT_STR_EQ(btn.text, "OK");
    ASSERT_NOT_NULL(btn.base.vtable.draw);
    ASSERT_NOT_NULL(btn.base.vtable.msgHandler);
    ASSERT_NOT_NULL(btn.base.vtable.destruct);
    ASSERT_NOT_NULL(btn.onClick);
    ASSERT_NOT_NULL(btn.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(btn.base.commonMsgHandlers.refresh);

    ASSERT_UINT_EQ(btn.base.index, DefaultIndex);
    ASSERT_UINT_EQ(btn.base.childCount, DefaultIndex);
    ASSERT_NULL(btn.base.windowHandler);

    free(btn.text);
}

static void testControlButtonMaxLabelLen(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));

    char longText[BtnMax * Two];
    memset(longText, 'X', sizeof(longText) - 1);
    longText[sizeof(longText) - 1] = '\0';

    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX,
                           longText, NULL, dummyOnClick, dummyCbBtn,
                           dummyCbBtn);

    ASSERT_NOT_NULL(btn.text);
    ASSERT_UINT_EQ(strlen(btn.text), (size_t)(BTN_LABEL_MAXLEN - 1));
    ASSERT_TRUE(btn.text[BTN_LABEL_MAXLEN - 1] == '\0');

    free(btn.text);
}

/* ────────────────── ControlGrid tests ───────────────────────────────────── */

static void testControlGridConstruct(void) {
    ControlGrid grid;
    memset(&grid, 0, sizeof(grid));

    controlGridConstruct(&grid, TestHeight, TestWidth, TestY, TestX,
                         LayoutVertical, TestHmargin, TestVmargin,
                         NULL, dummyCbGrid, dummyCbGrid, NULL);

    ASSERT_FALSE(grid.base.focusable);
    ASSERT_TRUE(grid.base.isContainer);
    ASSERT_FALSE(grid.base.focused);
    ASSERT_FALSE(grid.base.isPage);
    ASSERT_FALSE(grid.base.takeOverInput);
    ASSERT_TRUE(grid.base.visible);
    ASSERT_UINT_EQ(grid.layoutCounter, DefaultIndex);
    ASSERT_UINT_EQ(grid.layoutAccCol, DefaultIndex);
    ASSERT_UINT_EQ(grid.layoutAccRow, DefaultIndex);
    ASSERT_UINT_EQ(grid.margin.vertical, TestVmargin);
    ASSERT_UINT_EQ(grid.margin.horizontal, TestHmargin);

    ASSERT_INT_EQ(grid.layoutMethod, LayoutVertical);

    ASSERT_NOT_NULL(grid.base.vtable.draw);
    ASSERT_NOT_NULL(grid.base.vtable.msgHandler);
    ASSERT_NULL(grid.base.vtable.destruct);
    ASSERT_NOT_NULL(grid.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(grid.base.commonMsgHandlers.refresh);
    ASSERT_NULL(grid.base.windowHandler);

    ASSERT_UINT_EQ(grid.base.index, DefaultIndex);
    ASSERT_UINT_EQ(grid.base.childCount, DefaultIndex);
}

/* ────────────────── ControlLabel tests ──────────────────────────────────── */

static void testControlLabelConstruct(void) {
    ControlLabel label;
    memset(&label, 0, sizeof(label));

    controlLabelConstruct(&label, "PacPlay", TestY, TestX,
                          NULL, dummyCbLabel, dummyCbLabel);

    ASSERT_FALSE(label.base.focusable);
    ASSERT_FALSE(label.base.isContainer);
    ASSERT_FALSE(label.base.focused);
    ASSERT_FALSE(label.base.isPage);
    ASSERT_FALSE(label.base.takeOverInput);
    ASSERT_TRUE(label.base.visible);
    ASSERT_INT_EQ(label.base.y, TestY);
    ASSERT_INT_EQ(label.base.x, TestX);
    ASSERT_INT_EQ(label.base.height, One);
    ASSERT_INT_EQ(label.base.width, (int)strlen("PacPlay"));
    ASSERT_NOT_NULL(label.text);
    ASSERT_STR_EQ(label.text, "PacPlay");
    ASSERT_NOT_NULL(label.base.vtable.draw);
    ASSERT_NOT_NULL(label.base.vtable.msgHandler);
    ASSERT_NOT_NULL(label.base.vtable.destruct);
    ASSERT_NOT_NULL(label.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(label.base.commonMsgHandlers.refresh);

    free(label.text);
}

/* ────────────────── ControlInputBox tests ───────────────────────────────── */

static void testControlInputBoxConstruct(void) {
    ControlInputBox box;
    memset(&box, 0, sizeof(box));
    gClickCount = 0;

    controlInputBoxConstruct(&box, TestWidth, TestY, TestX,
                             NULL, dummyCbInputBox,
                             dummyOnSubmit, dummyCbInputBox);

    ASSERT_TRUE(box.base.focusable);
    ASSERT_FALSE(box.base.isContainer);
    ASSERT_FALSE(box.base.focused);
    ASSERT_FALSE(box.base.isPage);
    /* takeOverInput enabled on focus, not at construction. */
    ASSERT_FALSE(box.base.takeOverInput);
    ASSERT_TRUE(box.base.visible);
    ASSERT_INT_EQ(box.base.width, TestWidth);
    ASSERT_INT_EQ(box.base.y, TestY);
    ASSERT_INT_EQ(box.base.x, TestX);
    ASSERT_UINT_EQ(box.curLen, DefaultIndex);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);
    ASSERT_UINT_EQ(box.curLoc, DefaultIndex);
    ASSERT_NOT_NULL(box.buf);
    ASSERT_NOT_NULL(box.submit);
    ASSERT_NOT_NULL(box.base.vtable.draw);
    ASSERT_NOT_NULL(box.base.vtable.msgHandler);
    ASSERT_NOT_NULL(box.base.vtable.destruct);
    ASSERT_NOT_NULL(box.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(box.base.commonMsgHandlers.refresh);

    free(box.buf);
}

static void testControlInputBoxMinWidthClamp(void) {
    ControlInputBox box;
    memset(&box, 0, sizeof(box));

    controlInputBoxConstruct(&box, SmallWidth, TestY, TestX,
                             NULL, dummyCbInputBox,
                             dummyOnSubmit, dummyCbInputBox);

    ASSERT_INT_EQ(box.base.width, MinWidth);

    free(box.buf);
}

/* ────────────────── InputBox text manipulation tests ────────────────────── */

static void setupInputBox(ControlInputBox *box) {
    memset(box, 0, sizeof(*box));
    gClickCount = 0;
    controlInputBoxConstruct(box, InputMax, TestY, TestX,
                             NULL, dummyCbInputBox,
                             dummyOnSubmit, dummyCbInputBox);
}

static void teardownInputBox(ControlInputBox *box) {
    free(box->buf);
}

static void testInputBoxInsertSingle(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msg = {.type = MsgInput, .arg1 = {.input = 'A'}};
    box.base.vtable.msgHandler(&box, msg);

    ASSERT_UINT_EQ(box.curLen, One);
    ASSERT_UINT_EQ(box.curLoc, One);
    ASSERT_TRUE(box.buf[IntZero] == 'A');

    teardownInputBox(&box);
}

static void testInputBoxBackspace(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgA = {.type = MsgInput, .arg1 = {.input = 'A'}};
    TuiMsg msgB = {.type = MsgInput, .arg1 = {.input = 'B'}};
    box.base.vtable.msgHandler(&box, msgA);
    box.base.vtable.msgHandler(&box, msgB);
    ASSERT_UINT_EQ(box.curLen, Two);

    TuiMsg msgBS = {.type = MsgInput, .arg1 = {.input = KEY_BACKSPACE}};
    box.base.vtable.msgHandler(&box, msgBS);
    ASSERT_UINT_EQ(box.curLen, One);
    ASSERT_UINT_EQ(box.curLoc, One);
    ASSERT_TRUE(box.buf[IntZero] == 'A');

    teardownInputBox(&box);
}

static void testInputBoxDelete(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgA = {.type = MsgInput, .arg1 = {.input = 'A'}};
    TuiMsg msgB = {.type = MsgInput, .arg1 = {.input = 'B'}};
    box.base.vtable.msgHandler(&box, msgA);
    box.base.vtable.msgHandler(&box, msgB);

    TuiMsg msgLeft = {.type = MsgInput, .arg1 = {.input = KEY_LEFT}};
    box.base.vtable.msgHandler(&box, msgLeft);
    ASSERT_UINT_EQ(box.curLoc, One);

    TuiMsg msgDC = {.type = MsgInput, .arg1 = {.input = KEY_DC}};
    box.base.vtable.msgHandler(&box, msgDC);
    ASSERT_UINT_EQ(box.curLen, One);
    ASSERT_UINT_EQ(box.curLoc, One);
    ASSERT_TRUE(box.buf[IntZero] == 'A');

    teardownInputBox(&box);
}

static void testInputBoxCursorHomeEnd(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgA = {.type = MsgInput, .arg1 = {.input = 'A'}};
    TuiMsg msgB = {.type = MsgInput, .arg1 = {.input = 'B'}};
    box.base.vtable.msgHandler(&box, msgA);
    box.base.vtable.msgHandler(&box, msgB);

    TuiMsg msgHome = {.type = MsgInput, .arg1 = {.input = KEY_HOME}};
    box.base.vtable.msgHandler(&box, msgHome);
    ASSERT_UINT_EQ(box.curLoc, DefaultIndex);

    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler(&box, msgEnd);
    ASSERT_UINT_EQ(box.curLoc, Two);

    teardownInputBox(&box);
}

static void testInputBoxBufferFull(void) {
    ControlInputBox box;
    setupInputBox(&box);

    for (int i = 0; i < OverMax; i++) {
        TuiMsg msg = {.type = MsgInput, .arg1 = {.input = 'X'}};
        box.base.vtable.msgHandler(&box, msg);
    }

    ASSERT_UINT_EQ(box.curLen, (size_t)INPUTBOX_BUF_MAX_LEN);
    ASSERT_UINT_EQ(box.curLoc, (size_t)INPUTBOX_BUF_MAX_LEN);

    teardownInputBox(&box);
}

static void testInputBoxNonPrintableReject(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgCtrl = {.type = MsgInput, .arg1 = {.input = '\x01'}};
    box.base.vtable.msgHandler(&box, msgCtrl);
    ASSERT_UINT_EQ(box.curLen, DefaultIndex);

    TuiMsg msgDel = {.type = MsgInput, .arg1 = {.input = DelChar}};
    box.base.vtable.msgHandler(&box, msgDel);
    ASSERT_UINT_EQ(box.curLen, DefaultIndex);

    teardownInputBox(&box);
}

static void testInputBoxInsertMiddle(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgA = {.type = MsgInput, .arg1 = {.input = 'A'}};
    TuiMsg msgC = {.type = MsgInput, .arg1 = {.input = 'C'}};
    box.base.vtable.msgHandler(&box, msgA);
    box.base.vtable.msgHandler(&box, msgC);

    TuiMsg msgLeft = {.type = MsgInput, .arg1 = {.input = KEY_LEFT}};
    box.base.vtable.msgHandler(&box, msgLeft);
    ASSERT_UINT_EQ(box.curLoc, One);

    TuiMsg msgB = {.type = MsgInput, .arg1 = {.input = 'B'}};
    box.base.vtable.msgHandler(&box, msgB);

    ASSERT_UINT_EQ(box.curLen, Three);
    ASSERT_UINT_EQ(box.curLoc, Two);
    ASSERT_TRUE(box.buf[IntZero] == 'A');
    ASSERT_TRUE(box.buf[IntOne] == 'B');
    ASSERT_TRUE(box.buf[IntTwo] == 'C');

    teardownInputBox(&box);
}

static void testInputBoxEscReleases(void) {
    ControlInputBox box;
    setupInputBox(&box);
    /* Simulate focus to enable takeOverInput. */
    box.base.takeOverInput = true;
    ASSERT_TRUE(box.base.takeOverInput);

    TuiMsg msgEsc = {.type = MsgInput, .arg1 = {.input = '\e'}};
    box.base.vtable.msgHandler(&box, msgEsc);
    ASSERT_FALSE(box.base.takeOverInput);

    teardownInputBox(&box);
}

static void testInputBoxSubmitCallback(void) {
    ControlInputBox box;
    setupInputBox(&box);
    gClickCount = 0;

    TuiMsg msgEnter = {.type = MsgInput, .arg1 = {.input = '\n'}};
    box.base.vtable.msgHandler(&box, msgEnter);

    ASSERT_INT_EQ(gClickCount, One);
    ASSERT_FALSE(box.base.takeOverInput);

    teardownInputBox(&box);
}

/* ────────────────── double-destruct safety tests ────────────────────────── */

static void testControlButtonDestructDoubleSafe(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));
    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, "X",
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn);
    free(btn.text);
    btn.text = NULL;
}

static void testControlLabelDestructDoubleSafe(void) {
    ControlLabel label;
    memset(&label, 0, sizeof(label));
    controlLabelConstruct(&label, "X", TestY, TestX,
                          NULL, dummyCbLabel, dummyCbLabel);
    free(label.text);
    label.text = NULL;
}

static void testControlInputBoxDestructDoubleSafe(void) {
    ControlInputBox box;
    memset(&box, 0, sizeof(box));
    controlInputBoxConstruct(&box, TestWidth, TestY, TestX,
                             NULL, dummyCbInputBox,
                             dummyOnSubmit, dummyCbInputBox);
    free(box.buf);
    box.buf = NULL;
}

/* ════════════════════════════════════════════════════════════════════════
   main
   ════════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("test_tui_control:\n");

    /* Page */
    RUN_TEST(testControlPageConstruct);

    /* Button */
    RUN_TEST(testControlButtonConstruct);
    RUN_TEST(testControlButtonMaxLabelLen);

    /* Grid */
    RUN_TEST(testControlGridConstruct);

    /* Label */
    RUN_TEST(testControlLabelConstruct);

    /* InputBox construction */
    RUN_TEST(testControlInputBoxConstruct);
    RUN_TEST(testControlInputBoxMinWidthClamp);

    /* InputBox text manipulation */
    RUN_TEST(testInputBoxInsertSingle);
    RUN_TEST(testInputBoxBackspace);
    RUN_TEST(testInputBoxDelete);
    RUN_TEST(testInputBoxCursorHomeEnd);
    RUN_TEST(testInputBoxBufferFull);
    RUN_TEST(testInputBoxNonPrintableReject);
    RUN_TEST(testInputBoxInsertMiddle);
    RUN_TEST(testInputBoxEscReleases);
    RUN_TEST(testInputBoxSubmitCallback);

    /* Destruct safety */
    RUN_TEST(testControlButtonDestructDoubleSafe);
    RUN_TEST(testControlLabelDestructDoubleSafe);
    RUN_TEST(testControlInputBoxDestructDoubleSafe);

    return TEST_REPORT();
}
