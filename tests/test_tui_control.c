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

#include "test_utils.h"
#include "tui/control.h"
#include "tui/tuimsg.h"

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
    DelChar = 0x7F,
    TextBoxTestWidth = 12,
    TextBoxTestHeight = 5,
    TextBoxMinH = 3,
    TextBoxMinW = 3,
    TextBoxVisibleLines = 3,
    TextBoxAvailWidth = 10,
    Buf4096 = 4096,
    TwoLines = 2,
    ZeroLines = 0,
    /* Selection test coordinates (window-local, row 1 = first content line) */
    SelY1 = 1,
    SelY2 = 2,
    SelY3 = 3,
    SelX1 = 1,
    SelX3 = 3,
    SelX5 = 5,
    SelX6 = 6,
    /* Byte offsets for "line1\\nline2\\nline3\\nline4\\nline5" (29 chars) */
    SelByteLine1End = 5,
    SelByteLine2Start = 6,
    SelByteLine2End = 11,
    SelByteLine3Start = 12,
    SelByteLine3End = 17,
    SelByteTextEnd = 29,
    ScrollTextBoxDefMax = 100
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
static void dummyCbTextBox(ControlTextBox *self) { (void)self; }
static void dummyCbScrollTextBox(ControlScrollTextBox *self) { (void)self; }

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
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn, NULL);

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

    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, longText,
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn, NULL);

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
                         LayoutVertical, TestHmargin, TestVmargin, NULL,
                         dummyCbGrid, dummyCbGrid, NULL, NULL);

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

    controlLabelConstruct(&label, "PacPlay", DefaultIndex, TestY, TestX, NULL,
                          dummyCbLabel, dummyCbLabel, NULL);

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

    controlInputBoxConstruct(&box, TestWidth, TestY, TestX, false,
                             dummyCbInputBox, dummyCbInputBox, dummyOnSubmit,
                             dummyCbInputBox, NULL);

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

    controlInputBoxConstruct(&box, SmallWidth, TestY, TestX, false,
                             dummyCbInputBox, dummyCbInputBox, dummyOnSubmit,
                             dummyCbInputBox, NULL);

    ASSERT_INT_EQ(box.base.width, MinWidth);

    free(box.buf);
}

/* ────────────────── InputBox text manipulation tests ────────────────────── */

static void setupInputBox(ControlInputBox *box) {
    memset(box, 0, sizeof(*box));
    gClickCount = 0;
    controlInputBoxConstruct(box, InputMax, TestY, TestX, false,
                             dummyCbInputBox, dummyCbInputBox, dummyOnSubmit,
                             dummyCbInputBox, NULL);
}

static void teardownInputBox(ControlInputBox *box) { free(box->buf); }

static void testInputBoxInsertSingle(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msg = {.type = MsgInput, .arg1 = {.input = 'A'}};
    box.base.vtable.msgHandler((Control *)&box, msg);

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
    box.base.vtable.msgHandler((Control *)&box, msgA);
    box.base.vtable.msgHandler((Control *)&box, msgB);
    ASSERT_UINT_EQ(box.curLen, Two);

    TuiMsg msgBS = {.type = MsgInput, .arg1 = {.input = KEY_BACKSPACE}};
    box.base.vtable.msgHandler((Control *)&box, msgBS);
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
    box.base.vtable.msgHandler((Control *)&box, msgA);
    box.base.vtable.msgHandler((Control *)&box, msgB);

    TuiMsg msgLeft = {.type = MsgInput, .arg1 = {.input = KEY_LEFT}};
    box.base.vtable.msgHandler((Control *)&box, msgLeft);
    ASSERT_UINT_EQ(box.curLoc, One);

    TuiMsg msgDC = {.type = MsgInput, .arg1 = {.input = KEY_DC}};
    box.base.vtable.msgHandler((Control *)&box, msgDC);
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
    box.base.vtable.msgHandler((Control *)&box, msgA);
    box.base.vtable.msgHandler((Control *)&box, msgB);

    TuiMsg msgHome = {.type = MsgInput, .arg1 = {.input = KEY_HOME}};
    box.base.vtable.msgHandler((Control *)&box, msgHome);
    ASSERT_UINT_EQ(box.curLoc, DefaultIndex);

    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler((Control *)&box, msgEnd);
    ASSERT_UINT_EQ(box.curLoc, Two);

    teardownInputBox(&box);
}

static void testInputBoxBufferFull(void) {
    ControlInputBox box;
    setupInputBox(&box);

    for (int i = 0; i < OverMax; i++) {
        TuiMsg msg = {.type = MsgInput, .arg1 = {.input = 'X'}};
        box.base.vtable.msgHandler((Control *)&box, msg);
    }

    ASSERT_UINT_EQ(box.curLen, (size_t)INPUTBOX_BUF_MAX_LEN);
    ASSERT_UINT_EQ(box.curLoc, (size_t)INPUTBOX_BUF_MAX_LEN);

    teardownInputBox(&box);
}

static void testInputBoxNonPrintableReject(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgCtrl = {.type = MsgInput, .arg1 = {.input = '\x01'}};
    box.base.vtable.msgHandler((Control *)&box, msgCtrl);
    ASSERT_UINT_EQ(box.curLen, DefaultIndex);

    TuiMsg msgDel = {.type = MsgInput, .arg1 = {.input = DelChar}};
    box.base.vtable.msgHandler((Control *)&box, msgDel);
    ASSERT_UINT_EQ(box.curLen, DefaultIndex);

    teardownInputBox(&box);
}

static void testInputBoxInsertMiddle(void) {
    ControlInputBox box;
    setupInputBox(&box);

    TuiMsg msgA = {.type = MsgInput, .arg1 = {.input = 'A'}};
    TuiMsg msgC = {.type = MsgInput, .arg1 = {.input = 'C'}};
    box.base.vtable.msgHandler((Control *)&box, msgA);
    box.base.vtable.msgHandler((Control *)&box, msgC);

    TuiMsg msgLeft = {.type = MsgInput, .arg1 = {.input = KEY_LEFT}};
    box.base.vtable.msgHandler((Control *)&box, msgLeft);
    ASSERT_UINT_EQ(box.curLoc, One);

    TuiMsg msgB = {.type = MsgInput, .arg1 = {.input = 'B'}};
    box.base.vtable.msgHandler((Control *)&box, msgB);

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
    box.base.vtable.msgHandler((Control *)&box, msgEsc);
    ASSERT_FALSE(box.base.takeOverInput);

    teardownInputBox(&box);
}

static void testInputBoxSubmitCallback(void) {
    ControlInputBox box;
    setupInputBox(&box);
    gClickCount = 0;

    TuiMsg msgEnter = {.type = MsgInput, .arg1 = {.input = '\n'}};
    box.base.vtable.msgHandler((Control *)&box, msgEnter);

    ASSERT_INT_EQ(gClickCount, One);
    ASSERT_FALSE(box.base.takeOverInput);

    teardownInputBox(&box);
}

/* ────────────────── ControlTextBox tests ───────────────────────────────────
 */

static void testControlTextBoxConstruct(void) {
    ControlTextBox box;
    memset(&box, 0, sizeof(box));

    controlTextBoxConstruct(&box, TextBoxTestHeight, TextBoxTestWidth, TestY,
                            TestX, "Hello World", NULL, dummyCbTextBox,
                            dummyCbTextBox, NULL);

    ASSERT_TRUE(box.base.focusable);
    ASSERT_FALSE(box.base.isContainer);
    ASSERT_FALSE(box.base.focused);
    ASSERT_FALSE(box.base.isPage);
    ASSERT_FALSE(box.base.takeOverInput);
    ASSERT_TRUE(box.base.visible);
    ASSERT_INT_EQ(box.base.height, TextBoxTestHeight);
    ASSERT_INT_EQ(box.base.width, TextBoxTestWidth);
    ASSERT_INT_EQ(box.base.y, TestY);
    ASSERT_INT_EQ(box.base.x, TestX);
    ASSERT_NOT_NULL(box.text);
    ASSERT_STR_EQ(box.text, "Hello World");
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);
    ASSERT_NOT_NULL(box.base.vtable.draw);
    ASSERT_NOT_NULL(box.base.vtable.msgHandler);
    ASSERT_NOT_NULL(box.base.vtable.destruct);
    ASSERT_NOT_NULL(box.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(box.base.commonMsgHandlers.refresh);

    ASSERT_UINT_EQ(box.base.index, DefaultIndex);
    ASSERT_UINT_EQ(box.base.childCount, DefaultIndex);
    ASSERT_NULL(box.base.windowHandler);

    free(box.text);
}

static void testControlTextBoxMinSizeClamp(void) {
    ControlTextBox box;
    memset(&box, 0, sizeof(box));

    /* height < 3 and width < 3 should be clamped */
    controlTextBoxConstruct(&box, IntOne, IntOne, TestY, TestX, "A", NULL,
                            dummyCbTextBox, dummyCbTextBox, NULL);

    ASSERT_INT_EQ(box.base.height, TextBoxMinH);
    ASSERT_INT_EQ(box.base.width, TextBoxMinW);

    free(box.text);
}

static void testControlTextBoxMaxTextLen(void) {
    ControlTextBox box;
    memset(&box, 0, sizeof(box));

    char longText[Buf4096 * Two];
    memset(longText, 'X', sizeof(longText) - 1);
    longText[sizeof(longText) - 1] = '\0';

    controlTextBoxConstruct(&box, TextBoxTestHeight, TextBoxTestWidth, TestY,
                            TestX, longText, NULL, dummyCbTextBox,
                            dummyCbTextBox, NULL);

    ASSERT_NOT_NULL(box.text);
    ASSERT_UINT_EQ(strlen(box.text), (size_t)(TEXTBOX_TEXT_MAXLEN - 1));
    ASSERT_TRUE(box.text[TEXTBOX_TEXT_MAXLEN - 1] == '\0');

    free(box.text);
}

static void testControlTextBoxEmptyText(void) {
    ControlTextBox box;
    memset(&box, 0, sizeof(box));

    controlTextBoxConstruct(&box, TextBoxTestHeight, TextBoxTestWidth, TestY,
                            TestX, "", NULL, dummyCbTextBox, dummyCbTextBox,
                            NULL);

    ASSERT_NOT_NULL(box.text);
    ASSERT_UINT_EQ(box.textLen, DefaultIndex);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);

    free(box.text);
}

static void setupTextBox(ControlTextBox *box, const char *text) {
    memset(box, 0, sizeof(*box));
    controlTextBoxConstruct(box, TextBoxTestHeight, TextBoxTestWidth, TestY,
                            TestX, text, NULL, dummyCbTextBox, dummyCbTextBox,
                            NULL);
}

static void teardownTextBox(ControlTextBox *box) { free(box->text); }

static void testTextBoxScrollDownBoundary(void) {
    /* Text fits in one visual line when availWidth=10; maxView=0.
     * Scrolling down should not move viewBegin. */
    ControlTextBox box;
    setupTextBox(&box, "short");

    TuiMsg msgDown = {.type = MsgInput, .arg1 = {.input = KEY_DOWN}};
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);

    teardownTextBox(&box);
}

static void testTextBoxScrollDownMulti(void) {
    /* "line1\nline2\nline3\nline4\nline5" has 5 lines.
     * With visibleLines=3, maxView=2. */
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    TuiMsg msgDown = {.type = MsgInput, .arg1 = {.input = KEY_DOWN}};
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    ASSERT_UINT_EQ(box.viewBegin, One);
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    ASSERT_UINT_EQ(box.viewBegin, TwoLines);
    /* At boundary — no change */
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    ASSERT_UINT_EQ(box.viewBegin, TwoLines);

    teardownTextBox(&box);
}

static void testTextBoxScrollUpBoundary(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    TuiMsg msgDown = {.type = MsgInput, .arg1 = {.input = KEY_DOWN}};
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    box.base.vtable.msgHandler((Control *)&box, msgDown);
    ASSERT_UINT_EQ(box.viewBegin, TwoLines);

    TuiMsg msgUp = {.type = MsgInput, .arg1 = {.input = KEY_UP}};
    box.base.vtable.msgHandler((Control *)&box, msgUp);
    ASSERT_UINT_EQ(box.viewBegin, One);
    box.base.vtable.msgHandler((Control *)&box, msgUp);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);
    /* At upper boundary — no change */
    box.base.vtable.msgHandler((Control *)&box, msgUp);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);

    teardownTextBox(&box);
}

static void testTextBoxPageUpDown(void) {
    /* 9 lines with visibleLines=3 → maxView=6 */
    ControlTextBox box;
    setupTextBox(&box, "a\nb\nc\nd\ne\nf\ng\nh\ni");

    /* Page down by 3 */
    TuiMsg msgPgDn = {.type = MsgInput, .arg1 = {.input = KEY_NPAGE}};
    box.base.vtable.msgHandler((Control *)&box, msgPgDn);
    ASSERT_UINT_EQ(box.viewBegin, (size_t)TextBoxVisibleLines);

    /* Another page down to maxView (6) */
    box.base.vtable.msgHandler((Control *)&box, msgPgDn);
    ASSERT_UINT_EQ(box.viewBegin, (size_t)(TextBoxVisibleLines * TwoLines));

    /* Page up back to 3 */
    TuiMsg msgPgUp = {.type = MsgInput, .arg1 = {.input = KEY_PPAGE}};
    box.base.vtable.msgHandler((Control *)&box, msgPgUp);
    ASSERT_UINT_EQ(box.viewBegin, (size_t)TextBoxVisibleLines);

    teardownTextBox(&box);
}

static void testTextBoxHomeEnd(void) {
    /* 5 lines with visibleLines=3 → maxView=2 */
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler((Control *)&box, msgEnd);
    ASSERT_UINT_EQ(box.viewBegin, TwoLines);

    TuiMsg msgHome = {.type = MsgInput, .arg1 = {.input = KEY_HOME}};
    box.base.vtable.msgHandler((Control *)&box, msgHome);
    ASSERT_UINT_EQ(box.viewBegin, DefaultIndex);

    teardownTextBox(&box);
}

static void testTextBoxMouseScrollUp(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Scroll down first */
    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler((Control *)&box, msgEnd);
    ASSERT_UINT_EQ(box.viewBegin, TwoLines);

    /* Mouse scroll up */
    TuiMsg msgMouseUp = {.type = MsgMouse, .arg2 = {.input = BUTTON4_PRESSED}};
    box.base.vtable.msgHandler((Control *)&box, msgMouseUp);
    ASSERT_UINT_EQ(box.viewBegin, One);

    teardownTextBox(&box);
}

static void testTextBoxMouseScrollDown(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Mouse scroll down from top */
    TuiMsg msgMouseDn = {.type = MsgMouse, .arg2 = {.input = BUTTON5_PRESSED}};
    box.base.vtable.msgHandler((Control *)&box, msgMouseDn);
    ASSERT_UINT_EQ(box.viewBegin, One);

    teardownTextBox(&box);
}

static void testTextBoxVisualLineWordWrap(void) {
    /* Text: "hello world test" with availWidth=10.
     * "hello world" is 11 chars → wraps at space after "hello" (5 chars).
     * "world test" fits in 10 chars.
     * Total visual lines = 2. With visibleLines=3, maxView=0. */
    ControlTextBox box;
    setupTextBox(&box, "hello world test");

    /* END should set viewBegin to maxView = 0 */
    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler((Control *)&box, msgEnd);
    ASSERT_UINT_EQ(box.viewBegin, ZeroLines);

    teardownTextBox(&box);
}

static void testTextBoxVisualLineHardBreak(void) {
    /* Text: "abcdefghijklmnop" (16 chars no spaces) with availWidth=10.
     * Hard break every 10 chars → 2 visual lines. maxView = max(0, 2-3) = 0. */
    ControlTextBox box;
    setupTextBox(&box, "abcdefghijklmnop");

    TuiMsg msgEnd = {.type = MsgInput, .arg1 = {.input = KEY_END}};
    box.base.vtable.msgHandler((Control *)&box, msgEnd);
    ASSERT_UINT_EQ(box.viewBegin, ZeroLines);

    teardownTextBox(&box);
}

static void testTextBoxFocusToggle(void) {
    ControlTextBox box;
    setupTextBox(&box, "text");

    TuiMsg msgEnter = {.type = MsgFocusEnter};
    box.base.vtable.msgHandler((Control *)&box, msgEnter);
    ASSERT_TRUE(box.base.focused);

    TuiMsg msgLeave = {.type = MsgFocusLeave};
    box.base.vtable.msgHandler((Control *)&box, msgLeave);
    ASSERT_FALSE(box.base.focused);

    teardownTextBox(&box);
}

/* ────────────────── TextBox mouse selection tests ───────────────────────── */

static void testTextBoxSelectionPressStart(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.startByte, Zero);
    ASSERT_UINT_EQ(box.base.selection.endByte, Zero);

    teardownTextBox(&box);
}

static void testTextBoxSelectionPressSecondLine(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY2,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.startByte, SelByteLine2Start);

    teardownTextBox(&box);
}

static void testTextBoxSelectionPressPastEnd(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Click at (Y=1, X=6) — past end of "line1", should clamp to line end */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX6};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.startByte, SelByteLine1End);

    teardownTextBox(&box);
}

static void testTextBoxSelectionDragUpdate(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Start selection at begin of line1 */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_UINT_EQ(box.base.selection.startByte, Zero);

    /* Drag to end of line1 */
    TuiMsg msgDrag1 = {.type = MsgMouse,
                       .arg2 = {.input = REPORT_MOUSE_POSITION},
                       .mouseY = SelY1,
                       .mouseX = SelX6};
    box.base.vtable.msgHandler((Control *)&box, msgDrag1);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.endByte, SelByteLine1End);

    /* Drag to line2 */
    TuiMsg msgDrag2 = {.type = MsgMouse,
                       .arg2 = {.input = REPORT_MOUSE_POSITION},
                       .mouseY = SelY2,
                       .mouseX = SelX6};
    box.base.vtable.msgHandler((Control *)&box, msgDrag2);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.endByte, SelByteLine2End);

    /* Drag to line3 */
    TuiMsg msgDrag3 = {.type = MsgMouse,
                       .arg2 = {.input = REPORT_MOUSE_POSITION},
                       .mouseY = SelY3,
                       .mouseX = SelX6};
    box.base.vtable.msgHandler((Control *)&box, msgDrag3);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.endByte, SelByteLine3End);

    teardownTextBox(&box);
}

static void testTextBoxSelectionReleaseClears(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Press + drag + release: active must become false after release */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);

    TuiMsg msgDrag = {.type = MsgMouse,
                      .arg2 = {.input = REPORT_MOUSE_POSITION},
                      .mouseY = SelY1,
                      .mouseX = SelX5};
    box.base.vtable.msgHandler((Control *)&box, msgDrag);

    TuiMsg msgRelease = {.type = MsgMouse,
                         .arg2 = {.input = BUTTON1_RELEASED},
                         .mouseY = SelY1,
                         .mouseX = SelX5};
    box.base.vtable.msgHandler((Control *)&box, msgRelease);
    ASSERT_FALSE(box.base.selection.active);

    teardownTextBox(&box);
}

static void testTextBoxSelectionReverseNormalize(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Start at end, drag to start → endByte < startByte */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX5};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_UINT_EQ(box.base.selection.startByte, SelByteLine1End - 1);

    TuiMsg msgDrag = {.type = MsgMouse,
                      .arg2 = {.input = REPORT_MOUSE_POSITION},
                      .mouseY = SelY1,
                      .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgDrag);
    /* endByte should be less than startByte for reverse selection */
    ASSERT_UINT_EQ(box.base.selection.endByte, Zero);
    ASSERT_TRUE(box.base.selection.startByte > box.base.selection.endByte);

    /* Release: should normalize and copy — active cleared */
    TuiMsg msgRelease = {.type = MsgMouse,
                         .arg2 = {.input = BUTTON1_RELEASED},
                         .mouseY = SelY1,
                         .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgRelease);
    ASSERT_FALSE(box.base.selection.active);

    teardownTextBox(&box);
}

static void testTextBoxSelectionEmptyText(void) {
    ControlTextBox box;
    setupTextBox(&box, "");

    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    /* Empty text: selection should not activate or should be zero-length */
    ASSERT_UINT_EQ(box.base.selection.startByte, Zero);
    ASSERT_UINT_EQ(box.base.selection.endByte, Zero);

    TuiMsg msgRelease = {.type = MsgMouse,
                         .arg2 = {.input = BUTTON1_RELEASED},
                         .mouseY = SelY1,
                         .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgRelease);
    ASSERT_FALSE(box.base.selection.active);

    teardownTextBox(&box);
}

static void testTextBoxSelectionSingleChar(void) {
    ControlTextBox box;
    setupTextBox(&box, "a");

    /* Press + release at same position: one char selected, active cleared */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.selection.active);
    ASSERT_UINT_EQ(box.base.selection.startByte, Zero);

    TuiMsg msgRelease = {.type = MsgMouse,
                         .arg2 = {.input = BUTTON1_RELEASED},
                         .mouseY = SelY1,
                         .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgRelease);
    ASSERT_FALSE(box.base.selection.active);

    teardownTextBox(&box);
}

static void testScrollTextBoxSelectionPress(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));
    controlScrollTextBoxConstruct(&box, TextBoxTestHeight, TextBoxTestWidth,
                                  TestY, TestX, ScrollTextBoxDefMax, NULL,
                                  dummyCbScrollTextBox, dummyCbScrollTextBox,
                                  NULL);
    controlScrollTextBoxAppend(&box, "hello\nworld");

    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.base.selection.active);
    ASSERT_UINT_EQ(box.base.base.selection.startByte, Zero);

    /* Release to clear */
    TuiMsg msgRelease = {.type = MsgMouse,
                         .arg2 = {.input = BUTTON1_RELEASED},
                         .mouseY = SelY1,
                         .mouseX = SelX1};
    box.base.base.vtable.msgHandler((Control *)&box, msgRelease);
    ASSERT_FALSE(box.base.base.selection.active);

    free(box.base.text);
}

static void testButtonMouseClickFiresOnClick(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));
    gClickCount = 0;

    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, "OK",
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn, NULL);

    TuiMsg msgClick = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_RELEASED | BUTTON1_CLICKED}};
    btn.base.vtable.msgHandler((Control *)&btn, msgClick);
    ASSERT_INT_EQ(gClickCount, IntOne);

    free(btn.text);
}

static void testButtonMouseDragNoClick(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));
    gClickCount = 0;

    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, "OK",
                           NULL, dummyOnClick, dummyCbBtn, dummyCbBtn, NULL);

    TuiMsg msgRelease = {.type = MsgMouse, .arg2 = {.input = BUTTON1_RELEASED}};
    btn.base.vtable.msgHandler((Control *)&btn, msgRelease);
    ASSERT_INT_EQ(gClickCount, IntZero);

    free(btn.text);
}

static void testTextBoxMouseClickSwitchesFocus(void) {
    ControlTextBox box;
    setupTextBox(&box, "line1\nline2\nline3\nline4\nline5");

    /* Press starts selection */
    TuiMsg msgPress = {.type = MsgMouse,
                       .arg2 = {.input = BUTTON1_PRESSED},
                       .mouseY = SelY1,
                       .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgPress);
    ASSERT_TRUE(box.base.selection.active);

    /* Release with BUTTON1_CLICKED: no drag → no copy, but active cleared */
    TuiMsg msgClickRelease = {
        .type = MsgMouse,
        .arg2 = {.input = BUTTON1_RELEASED | BUTTON1_CLICKED},
        .mouseY = SelY1,
        .mouseX = SelX1};
    box.base.vtable.msgHandler((Control *)&box, msgClickRelease);
    ASSERT_FALSE(box.base.selection.active);

    teardownTextBox(&box);
}

/* ────────────────── double-destruct safety tests ────────────────────────── */

static void testControlButtonDestructDoubleSafe(void) {
    ControlButton btn;
    memset(&btn, 0, sizeof(btn));
    controlButtonConstruct(&btn, TestHeight, TestWidth, TestY, TestX, "X", NULL,
                           dummyOnClick, dummyCbBtn, dummyCbBtn, NULL);
    free(btn.text);
    btn.text = NULL;
}

static void testControlLabelDestructDoubleSafe(void) {
    ControlLabel label;
    memset(&label, 0, sizeof(label));
    controlLabelConstruct(&label, "X", DefaultIndex, TestY, TestX, NULL,
                          dummyCbLabel, dummyCbLabel, NULL);
    free(label.text);
    label.text = NULL;
}

static void testControlInputBoxDestructDoubleSafe(void) {
    ControlInputBox box;
    memset(&box, 0, sizeof(box));
    controlInputBoxConstruct(&box, TestWidth, TestY, TestX, false,
                             dummyCbInputBox, dummyCbInputBox, dummyOnSubmit,
                             dummyCbInputBox, NULL);
    free(box.buf);
    box.buf = NULL;
}

static void testControlTextBoxDestructDoubleSafe(void) {
    ControlTextBox box;
    memset(&box, 0, sizeof(box));
    controlTextBoxConstruct(&box, TextBoxTestHeight, TextBoxTestWidth, TestY,
                            TestX, "OK", NULL, dummyCbTextBox, dummyCbTextBox,
                            NULL);
    free(box.text);
    box.text = NULL;
}

/* ────────────────── ControlScrollTextBox tests ─────────────────────────────
 */

enum {
    ScrollTestWidth = 30,
    ScrollTestHeight = 5,
    ScrollTestVisible = 3,
    ScrollMaxLines = 3,
    ScrollMaxLinesSmall = 2,
    ScrollDefaultMax = 100,
    ScrollMinH = 3,
    ScrollMinW = 3,
    ScrollBuf65536 = 65536,
    ScrollLineChar = '\n'
};

static void dummyCbScrollBox(ControlScrollTextBox *self) { (void)self; }

static void testScrollTextBoxConstruct(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    ASSERT_TRUE(box.base.base.focusable);
    ASSERT_FALSE(box.base.base.isContainer);
    ASSERT_FALSE(box.base.base.focused);
    ASSERT_FALSE(box.base.base.isPage);
    ASSERT_FALSE(box.base.base.takeOverInput);
    ASSERT_TRUE(box.base.base.visible);
    ASSERT_INT_EQ(box.base.base.height, ScrollTestHeight);
    ASSERT_INT_EQ(box.base.base.width, ScrollTestWidth);
    ASSERT_INT_EQ(box.base.base.y, TestY);
    ASSERT_INT_EQ(box.base.base.x, TestX);
    ASSERT_NOT_NULL(box.base.text);
    ASSERT_UINT_EQ(box.base.textLen, DefaultIndex);
    ASSERT_UINT_EQ(box.base.viewBegin, DefaultIndex);
    ASSERT_UINT_EQ(box.maxLines, (size_t)ScrollMaxLines);
    ASSERT_NOT_NULL(box.base.base.vtable.draw);
    ASSERT_NOT_NULL(box.base.base.vtable.msgHandler);
    ASSERT_NOT_NULL(box.base.base.vtable.destruct);
    ASSERT_NOT_NULL(box.base.base.commonMsgHandlers.resize);
    ASSERT_NOT_NULL(box.base.base.commonMsgHandlers.refresh);
    ASSERT_UINT_EQ(box.base.base.index, DefaultIndex);
    ASSERT_UINT_EQ(box.base.base.childCount, DefaultIndex);
    ASSERT_NULL(box.base.base.windowHandler);

    free(box.base.text);
}

static void testScrollTextBoxMinSizeClamp(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, IntOne, IntOne, TestY, TestX,
                                  ScrollMaxLines, NULL, dummyCbScrollBox,
                                  dummyCbScrollBox, NULL);

    ASSERT_INT_EQ(box.base.base.height, ScrollMinH);
    ASSERT_INT_EQ(box.base.base.width, ScrollMinW);

    free(box.base.text);
}

static void testScrollTextBoxMaxLinesZero(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, IntZero, NULL, dummyCbScrollBox,
                                  dummyCbScrollBox, NULL);

    ASSERT_UINT_EQ(box.maxLines, (size_t)ScrollDefaultMax);

    free(box.base.text);
}

static void testScrollTextBoxAppendEmpty(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "");
    ASSERT_UINT_EQ(box.base.textLen, DefaultIndex);
    ASSERT_STR_EQ(box.base.text, "");

    controlScrollTextBoxAppend(&box, NULL);
    ASSERT_UINT_EQ(box.base.textLen, DefaultIndex);

    free(box.base.text);
}

static void testScrollTextBoxAppendSimple(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "hello");
    ASSERT_STR_EQ(box.base.text, "hello");
    ASSERT_UINT_EQ(box.base.textLen, (size_t)((int)strlen("hello")));

    free(box.base.text);
}

static void testScrollTextBoxAppendAccumulate(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "hello");
    controlScrollTextBoxAppend(&box, " world");
    ASSERT_STR_EQ(box.base.text, "hello world");

    free(box.base.text);
}

static void testScrollTextBoxAppendNewlines(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "line1\nline2\nline3");
    ASSERT_STR_EQ(box.base.text, "line1\nline2\nline3");

    free(box.base.text);
}

static void testScrollTextBoxAppendExceedMaxLines(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "a\nb\nc\nd\ne");
    ASSERT_STR_EQ(box.base.text, "c\nd\ne");

    free(box.base.text);
}

static void testScrollTextBoxAppendExactMaxLines(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "a\nb\nc");
    ASSERT_STR_EQ(box.base.text, "a\nb\nc");

    free(box.base.text);
}

static void testScrollTextBoxAppendIncrementalTrim(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLinesSmall, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "line1\n");
    ASSERT_STR_EQ(box.base.text, "line1\n");

    controlScrollTextBoxAppend(&box, "line2\n");
    ASSERT_STR_EQ(box.base.text, "line1\nline2\n");

    controlScrollTextBoxAppend(&box, "line3");
    ASSERT_STR_EQ(box.base.text, "line2\nline3");

    free(box.base.text);
}

static void testScrollTextBoxAppendOnlyNewlines(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    controlScrollTextBoxAppend(&box, "\n\n\n");
    ASSERT_UINT_EQ(box.base.textLen, (size_t)ScrollMaxLines);
    ASSERT_TRUE(box.base.text[0] == ScrollLineChar);
    ASSERT_TRUE(box.base.text[1] == ScrollLineChar);
    ASSERT_TRUE(box.base.text[2] == ScrollLineChar);

    free(box.base.text);
}

static void testScrollTextBoxDestructDoubleSafe(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLines, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);
    free(box.base.text);
    box.base.text = NULL;
}

static void testScrollTextBoxAppendVeryLongLine(void) {
    ControlScrollTextBox box;
    memset(&box, 0, sizeof(box));

    controlScrollTextBoxConstruct(&box, ScrollTestHeight, ScrollTestWidth,
                                  TestY, TestX, ScrollMaxLinesSmall, NULL,
                                  dummyCbScrollBox, dummyCbScrollBox, NULL);

    char longBuf[ScrollBuf65536 + (size_t)IntOne];
    memset(longBuf, 'X', ScrollBuf65536);
    longBuf[ScrollBuf65536] = '\0';

    controlScrollTextBoxAppend(&box, longBuf);
    ASSERT_UINT_EQ(box.base.textLen, (size_t)(SCROLLTEXTBOX_TEXT_MAXLEN - 1));
    ASSERT_TRUE(box.base.text[0] == 'X');

    free(box.base.text);
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
    RUN_TEST(testControlTextBoxDestructDoubleSafe);

    /* TextBox construction */
    RUN_TEST(testControlTextBoxConstruct);
    RUN_TEST(testControlTextBoxMinSizeClamp);
    RUN_TEST(testControlTextBoxMaxTextLen);
    RUN_TEST(testControlTextBoxEmptyText);

    /* TextBox scrolling */
    RUN_TEST(testTextBoxScrollDownBoundary);
    RUN_TEST(testTextBoxScrollDownMulti);
    RUN_TEST(testTextBoxScrollUpBoundary);
    RUN_TEST(testTextBoxPageUpDown);
    RUN_TEST(testTextBoxHomeEnd);
    RUN_TEST(testTextBoxMouseScrollUp);
    RUN_TEST(testTextBoxMouseScrollDown);

    /* TextBox visual line wrapping */
    RUN_TEST(testTextBoxVisualLineWordWrap);
    RUN_TEST(testTextBoxVisualLineHardBreak);

    /* TextBox focus */
    RUN_TEST(testTextBoxFocusToggle);

    /* ScrollTextBox construction */
    RUN_TEST(testScrollTextBoxConstruct);
    RUN_TEST(testScrollTextBoxMinSizeClamp);
    RUN_TEST(testScrollTextBoxMaxLinesZero);

    /* ScrollTextBox append */
    RUN_TEST(testScrollTextBoxAppendEmpty);
    RUN_TEST(testScrollTextBoxAppendSimple);
    RUN_TEST(testScrollTextBoxAppendAccumulate);
    RUN_TEST(testScrollTextBoxAppendNewlines);
    RUN_TEST(testScrollTextBoxAppendExceedMaxLines);
    RUN_TEST(testScrollTextBoxAppendExactMaxLines);
    RUN_TEST(testScrollTextBoxAppendIncrementalTrim);
    RUN_TEST(testScrollTextBoxAppendOnlyNewlines);
    RUN_TEST(testScrollTextBoxAppendVeryLongLine);

    /* ScrollTextBox destruct safety */
    RUN_TEST(testScrollTextBoxDestructDoubleSafe);

    /* ─────────── TextBox mouse selection ──────────────────────────────── */
    RUN_TEST(testTextBoxSelectionPressStart);
    RUN_TEST(testTextBoxSelectionPressSecondLine);
    RUN_TEST(testTextBoxSelectionPressPastEnd);
    RUN_TEST(testTextBoxSelectionDragUpdate);
    RUN_TEST(testTextBoxSelectionReleaseClears);
    RUN_TEST(testTextBoxSelectionReverseNormalize);
    RUN_TEST(testTextBoxSelectionEmptyText);
    RUN_TEST(testTextBoxSelectionSingleChar);
    RUN_TEST(testScrollTextBoxSelectionPress);
    RUN_TEST(testButtonMouseClickFiresOnClick);
    RUN_TEST(testButtonMouseDragNoClick);
    RUN_TEST(testTextBoxMouseClickSwitchesFocus);

    return TEST_REPORT();
}
