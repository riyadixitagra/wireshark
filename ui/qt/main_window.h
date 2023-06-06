/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <epan/prefs.h>
#include <epan/stat_groups.h>
#include <epan/frame_data.h>

// frame_data also available with this include in the original wireshark_main_window code
//#include "follow_stream_dialog.h"


#include "filter_action.h"

#include <QMainWindow>
#include <QSplitter>

class QSplitter;
class QStackedWidget;
class ByteViewTab;
class DisplayFilterCombo;
class FieldInformation;
class MainStatusBar;
class PacketDiagram;
class PacketList;
class ProtoTree;
class WelcomePage;

typedef struct _capture_file capture_file;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool hasSelection();
    bool hasUniqueSelection();
    QList<int> selectedRows(bool useFrameNum = false);
    void insertColumn(QString name, QString abbrev, gint pos = -1);
    void gotoFrame(int packet_num);
    frame_data* frameDataForRow(int) const;

    QString getFilter();
    MainStatusBar *statusBar();

    // Used for managing custom packet menus
    void appendPacketMenu(QAction* funnel_action);
    QList<QAction*> getPacketMenuActions();
    void clearAddedPacketMenus();
    bool addPacketMenus(QMenu * ctx_menu, GPtrArray *finfo_array);

public slots:
    void setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType);
    virtual void filterPackets(QString, bool) = 0;
    virtual void showPreferencesDialog(QString module_name) = 0;
    void layoutPanes();
    void applyRecentPaneGeometry();

protected:
    enum CopySelected {
        CopyAllVisibleItems,
        CopyAllVisibleSelectedTreeItems,
        CopySelectedDescription,
        CopySelectedFieldName,
        CopySelectedValue,
        CopyListAsText,
        CopyListAsCSV,
        CopyListAsYAML
    };

    void showWelcome();
    void showCapture();

    QList<register_stat_group_t> menu_groups_;
    QWidget* getLayoutWidget(layout_pane_content_e type);

    QStackedWidget *main_stack_;
    WelcomePage *welcome_page_;
    QSplitter master_split_;
    QSplitter extra_split_;
    QWidget empty_pane_;
    QVector<unsigned> cur_layout_;

    PacketList *packet_list_;
    ProtoTree *proto_tree_;
    ByteViewTab *byte_view_tab_;
    PacketDiagram *packet_diagram_;
    DisplayFilterCombo *df_combo_box_;
    MainStatusBar *main_status_bar_;

signals:
    void setCaptureFile(capture_file *cf);
    void fieldSelected(FieldInformation *);
    void framesSelected(QList<int>);
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
    void displayFilterSuccess(bool success);

};

#endif // MAINWINDOW_H
