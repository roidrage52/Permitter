# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController, IExtensionStateListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, FlowLayout
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JCheckBox, JButton, JScrollPane, BorderFactory, JMenuItem, JTable, JComboBox, ListSelectionModel, JSpinner, SpinnerNumberModel, JSplitPane, JFileChooser
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import ActionListener
import re
import threading
import time
import java.io.File
try:
    import json
except ImportError:
    import simplejson as json

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, ActionListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Permiter")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        self.roles = {}
        self.test_results = []
        self.target_scope = ""
        self.test_lock = threading.Lock()
        self.stop_testing = False
        self.current_testing_thread = None
        self.tested_urls = set()
        self.current_request_response = None
        self.createGUI()
        callbacks.addSuiteTab(self)
        print("Permiter")
        print("Author: Dave Blandford");
        print("Twitter: @hackr1ot")
        print("Email: dave@mailo.com");
        print(
        '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQGNBGSNEtsBDAC1UCGz94jKVspY7Arb32h+2dlUTM8tAJt/l+TF7T52MRiiVEX6
55AXr7UXfgzpT75c0GsH6rzfRG8pmXP08fCTzpiwpRZJK8PA+Fys2g10CRtw/Bt1
3G8mTKDmWOqQkcrpMzHgFfnFYOlyLpAvxoDrDEwl4l3sEYD6GPOGqKDZvFjiHgY/
jKh/+hSitjVFAiXbR/FVaR5W81LhFxlik/delK592n/BNCPygkavqASyFExBTFCJ
EJOH7wDQS/sUe11Npknh24JQJfDhaDRVeZ3ik0y3cuMSiNjehskzfG5AmTV6PVPm
VFITwpZ8hCRsB4ciP35OkJ8eVDpSHeI1i0wBEbrqWzReag6HpCRopffQL1yiO6Om
6UJ30vXFd3+PrKMuyVTq34e68R5yRY2PiHBdPbbnp2DDQv0d77H9zSkn/lJNIbcC
VotKwCi2C/Q1NiyaxneXfrlnyA1rRFn6ozuqvFjQt6NzwwjKTPj/pAZsu7a6VfPc
tmVEnv3vdOH9QwcAEQEAAbQfZGF2ZUBtYWlsby5jb20gPGRhdmVAbWFpbG8uY29t
PokBsAQTAQoAGgQLCQgHAhUKAhYBAhkBBYJkjRLbAp4BApsDAAoJEPIgx29nyJfw
HiQMAJ5gQXTHAWCHPtgspu0FQG8aSHVNhgkpydRVAiU5aYjxXGcyobFGupvoc2Gk
9+TaFBBCHI22qrMs41YeUTVIJLF1OHoTjJGHMtq2PoJdcO6ys/Gf5v4AX9fzfblk
EMKvLv1wB+GehAQE25AroYqoOI+hLae4fHA0WL7veLhXEtqpH1qt1+4DHzGD2Rzo
9WGBrsAlPIG1YCh5F1g1nxBEbGR/TL+76t9PIH+y7WHOyWMmLQw3IYqKg6OtlipH
re9fFco1kgrZuP1Hi16vklNe/10xpD1T+En7u4JWxos4YYw7RhQ/Kcpw1nrxvBGJ
Fxisn165lyhAIeMqdj3lZrZFGYLyaNkWwfSDZ6MHdb40mj2irMOgm1F+vC+rESeM
84+HNGnnhGxhmKdRdUAMlJRt0pwEEU9Pbn3VfNFmKSRmvRVR2SM+PGTFz2gUErpO
UgbllXSwqO/EcnLcQ/+wrtXHReScsQIFXDkoEQgs1t4kHC5xHsAYTxOMQkBJxSR3
YQLHVbkBjQRkjRLbAQwAnUlq4VLwvevWsiuyJRsMleUAQsuvDotTQ+8675nqznCU
km5SaMU22rpeWXmZwOnFsQqKV82ARfNpEBXKeLWZlEBas+q8nWCkKqkWN7tEFKKk
4MnmMnzplKj5NVCQu7xpaf8niIbF6VIubO3qj0j5Gq6Yk7m15ROIJH/bpvJMQ2Ol
2zO2kyKIm5fIjD/M/IWClCoZtTWDwUSgF3EzrSDsqdGIjXW2qyyfhxOct1B3s+lB
bWLkBUzm/54NqizgkgpUJtbnnVNcgQBGHg9TB/ZjmbyrSHY4g2DG0qA3Z8Qo2M08
J9SfFG731wQO87RtCpCdIKSOvHjLVT4sdqUHRyIWye1lABwyvbcpxVwcsOImLC8H
iy9RrqdmZdgI5bdEVHTmfHUFahTGWYjmiBU37yCe0YtnL5LMHXpS7z7cfuEvAkRG
FWV0J0OP1Zv/gPhWg2zIU3JN3j/vydFnimXvxWiY6W3LDm+FtxGo4Vnv43LbDbo6
076oEHq1jdzt45b9zVFhABEBAAGJAbYEGAEKAAkFgmSNEtsCmwwAIQkQ8iDHb2fI
l/AWIQRGhTbxG1Jvt4C3axzyIMdvZ8iX8Jl2C/4qT8oqTOqP37pADcQUbcpxrixB
S79HxvyjoSCUihW4MVcYF/86gvhVrCCLShEnDEQrLRELzKyCPL67wESb5wUvEtdY
H40dEopUOHSyWN2TnCbdP1Pdxso42E3UC97HrpGG2CpUF4dFdzeivj4h60QGZmVF
PD6Tqp6Mk9RfYXGDGiOgAOZoVM15aMvykSQnXJg7d2WMB4mDg8ozQAjXF3DIq9R7
X5KiWQE03BYBowZFipNVR4uVwSC7ni7vhu3PsatDCXpo+LNUkZ1nOykZQN/l8UZJ
xjG6Su8XG20EELWQbiq5JelREzhew4IPlPzJE8Ue559SzmP8RJCR9Tjqpe3oJYaL
s6giNTcizv/Ph+uj7w5Rykqy7rdmtDh9h3Q9NpVhOcJeQCxj8sWzbmNOx91nhmvD
9XcoMbAbJuiuWIEl9/iSJxe6NNxKQcJYjRk3jqk+H8DMgk+cXdKy+H/0dFrznO4f
JSYTJzaX2Ds2ClCwTyz5P4Gjx6CoKwBIdsEspog=
=iIJQ
-----END PGP PUBLIC KEY BLOCK-----
        '''
        )

    def extensionUnloaded(self):
        self.stop_testing = True
        if self.current_testing_thread and self.current_testing_thread.isAlive():
            self.current_testing_thread.join(5)

    def createGUI(self):
        self.panel = JPanel(BorderLayout())
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split.setResizeWeight(0.5)
        top_panel = JPanel(BorderLayout())
        config_section = JPanel(BorderLayout())
        config_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        config_split.setResizeWeight(0.5)
        left_config = JPanel(GridBagLayout())
        left_gbc = GridBagConstraints()
        left_gbc.insets = Insets(3, 3, 3, 3)
        left_gbc.anchor = GridBagConstraints.NORTHWEST
        left_gbc.weighty = 1.0  
        left_gbc.gridx = 0; left_gbc.gridy = 0; left_gbc.weightx = 0
        left_config.add(JLabel("Target Scope:"), left_gbc)
        left_gbc.gridx = 1; left_gbc.fill = GridBagConstraints.NONE; left_gbc.weightx = 0
        scope_options_panel = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
        self.scope_method_combo = JComboBox(["Target History", "Custom Regex"])
        self.scope_method_combo.addActionListener(self)
        scope_options_panel.add(self.scope_method_combo)
        self.refresh_targets_button = JButton("Refresh Targets")
        self.refresh_targets_button.addActionListener(self)
        scope_options_panel.add(self.refresh_targets_button)
        left_config.add(scope_options_panel, left_gbc)
        left_gbc.gridx = 0; left_gbc.gridy = 1; left_gbc.weightx = 0
        left_config.add(JLabel("Select Target:"), left_gbc)
        left_gbc.gridx = 1; left_gbc.fill = GridBagConstraints.HORIZONTAL; left_gbc.weightx = 1.0
        self.target_combo = JComboBox()
        self.target_combo.addActionListener(self)
        left_config.add(self.target_combo, left_gbc)
        left_gbc.gridx = 0; left_gbc.gridy = 2; left_gbc.weightx = 0
        left_config.add(JLabel("Scope Pattern:"), left_gbc)
        left_gbc.gridx = 1; left_gbc.fill = GridBagConstraints.HORIZONTAL; left_gbc.weightx = 1.0
        self.scope_field = JTextField("https://hackedsite\\.uhoh/.*", 30)
        left_config.add(self.scope_field, left_gbc)
        left_gbc.gridx = 0; left_gbc.gridy = 3; left_gbc.weightx = 0
        left_config.add(JLabel("Exclude Endpoints:"), left_gbc)
        left_gbc.gridx = 1; left_gbc.fill = GridBagConstraints.HORIZONTAL; left_gbc.weightx = 1.0
        self.exclude_field = JTextField("/password_reset,/logout,/login")
        self.exclude_field.setToolTipText("Comma-separated list of endpoints to exclude")
        left_config.add(self.exclude_field, left_gbc)
        left_gbc.gridx = 0; left_gbc.gridy = 4; left_gbc.weightx = 0
        left_config.add(JLabel("Request Delay (ms):"), left_gbc)
        left_gbc.gridx = 1; left_gbc.fill = GridBagConstraints.NONE; left_gbc.weightx = 0
        self.delay_spinner = JSpinner(SpinnerNumberModel(10, 0, 1000, 5))
        left_config.add(self.delay_spinner, left_gbc)
        left_gbc.gridx = 0; left_gbc.gridy = 5; left_gbc.gridwidth = 2; left_gbc.fill = GridBagConstraints.HORIZONTAL
        testing_panel = JPanel(GridBagLayout())
        testing_gbc = GridBagConstraints()
        testing_gbc.insets = Insets(2, 2, 2, 2)
        testing_gbc.anchor = GridBagConstraints.WEST
        testing_gbc.gridx = 0; testing_gbc.gridy = 0
        self.test_history_button = JButton("Use Proxy History")
        self.test_history_button.addActionListener(self)
        testing_panel.add(self.test_history_button, testing_gbc)
        testing_gbc.gridx = 1
        self.test_target_button = JButton("Use Site Map")
        self.test_target_button.addActionListener(self)
        testing_panel.add(self.test_target_button, testing_gbc)
        testing_gbc.gridx = 2
        self.stop_test_button = JButton("Stop Testing")
        self.stop_test_button.addActionListener(self)
        self.stop_test_button.setEnabled(False)
        testing_panel.add(self.stop_test_button, testing_gbc)
        testing_gbc.gridx = 0; testing_gbc.gridy = 1
        self.save_state_button = JButton("Save State")
        self.save_state_button.addActionListener(self)
        testing_panel.add(self.save_state_button, testing_gbc)
        testing_gbc.gridx = 1
        self.load_state_button = JButton("Load State")
        self.load_state_button.addActionListener(self)
        testing_panel.add(self.load_state_button, testing_gbc)
        testing_gbc.gridx = 2
        self.clear_results_button = JButton("Clear Results")
        self.clear_results_button.addActionListener(self)
        testing_panel.add(self.clear_results_button, testing_gbc)
        testing_gbc.gridx = 0; testing_gbc.gridy = 2
        self.export_csv_button = JButton("Export CSV")
        self.export_csv_button.addActionListener(self)
        testing_panel.add(self.export_csv_button, testing_gbc)
        testing_gbc.gridx = 1
        self.export_html_button = JButton("Export HTML")
        self.export_html_button.addActionListener(self)
        testing_panel.add(self.export_html_button, testing_gbc)
        testing_gbc.gridx = 2
        self.test_unauth_checkbox = JCheckBox("Include Unauth", False)
        testing_panel.add(self.test_unauth_checkbox, testing_gbc)
        testing_gbc.gridx = 0; testing_gbc.gridy = 3
        self.use_entire_history_checkbox = JCheckBox("Use Entire History", False)
        self.use_entire_history_checkbox.setToolTipText("Test all requests without removing duplicates")
        testing_panel.add(self.use_entire_history_checkbox, testing_gbc)
        testing_gbc.gridx = 0; testing_gbc.gridy = 4; testing_gbc.gridwidth = 1
        skip_label = JLabel("Skip Static:")
        testing_panel.add(skip_label, testing_gbc)
        testing_gbc.gridx = 1; testing_gbc.gridwidth = 2
        skip_panel = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
        self.skip_js_checkbox = JCheckBox("JS", True)
        self.skip_css_checkbox = JCheckBox("CSS", True)
        self.skip_images_checkbox = JCheckBox("Images", True)
        self.skip_fonts_checkbox = JCheckBox("Fonts", True)
        self.skip_media_checkbox = JCheckBox("Media", True)
        skip_panel.add(self.skip_js_checkbox)
        skip_panel.add(self.skip_css_checkbox)
        skip_panel.add(self.skip_images_checkbox)
        skip_panel.add(self.skip_fonts_checkbox)
        skip_panel.add(self.skip_media_checkbox)
        testing_panel.add(skip_panel, testing_gbc)
        left_config.add(testing_panel, left_gbc)
        config_split.setLeftComponent(left_config)
        right_config = JPanel(BorderLayout())
        role_controls_panel = JPanel(GridBagLayout())
        controls_gbc = GridBagConstraints()
        controls_gbc.insets = Insets(3, 3, 3, 3)
        controls_gbc.anchor = GridBagConstraints.WEST
        controls_gbc.gridx = 0; controls_gbc.gridy = 0; controls_gbc.weightx = 0
        role_controls_panel.add(JLabel("Roles:"), controls_gbc)
        controls_gbc.gridx = 0; controls_gbc.gridy = 1; controls_gbc.fill = GridBagConstraints.HORIZONTAL; controls_gbc.weightx = 0.5
        self.role_combo = JComboBox()
        self.role_combo.addActionListener(self)
        role_controls_panel.add(self.role_combo, controls_gbc)
        controls_gbc.gridx = 0; controls_gbc.gridy = 2; controls_gbc.fill = GridBagConstraints.NONE; controls_gbc.weightx = 0
        role_buttons_panel = JPanel(FlowLayout(FlowLayout.LEFT, 2, 2))
        self.add_role_button = JButton("Add New Role")
        self.add_role_button.addActionListener(self)
        role_buttons_panel.add(self.add_role_button)
        self.delete_role_button = JButton("Delete Role")
        self.delete_role_button.addActionListener(self)
        role_buttons_panel.add(self.delete_role_button)
        role_controls_panel.add(role_buttons_panel, controls_gbc)
        controls_gbc.gridx = 1; controls_gbc.gridy = 0; controls_gbc.weightx = 0
        role_controls_panel.add(JLabel("Role Name:"), controls_gbc)
        controls_gbc.gridx = 1; controls_gbc.gridy = 1; controls_gbc.fill = GridBagConstraints.HORIZONTAL; controls_gbc.weightx = 0.5
        self.role_name_field = JTextField("", 25)
        role_controls_panel.add(self.role_name_field, controls_gbc)
        right_config.add(role_controls_panel, BorderLayout.NORTH)
        patterns_panel = JPanel(BorderLayout())
        patterns_panel.setBorder(BorderFactory.createTitledBorder("Regex Patterns"))
        self.main_patterns_panel = JPanel(GridBagLayout())
        patterns_scroll = JScrollPane(self.main_patterns_panel)
        patterns_scroll.setPreferredSize(Dimension(600, 200))
        patterns_panel.add(patterns_scroll, BorderLayout.CENTER)
        pattern_button_panel = JPanel()
        self.add_pattern_button = JButton("Add Regex")
        self.add_pattern_button.addActionListener(self)
        pattern_button_panel.add(self.add_pattern_button)
        self.save_role_button = JButton("Save")
        self.save_role_button.addActionListener(self)
        pattern_button_panel.add(self.save_role_button)
        patterns_panel.add(pattern_button_panel, BorderLayout.SOUTH)
        right_config.add(patterns_panel, BorderLayout.CENTER)
        config_split.setRightComponent(right_config)
        config_section.add(config_split, BorderLayout.CENTER)
        top_panel.add(config_section, BorderLayout.CENTER)
        main_split.setTopComponent(top_panel)
        bottom_panel = JPanel(BorderLayout())
        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        bottom_split.setResizeWeight(0.5)
        test_section = JPanel(BorderLayout())
        self.results_table_model = DefaultTableModel()
        self.results_table_model.addColumn("Role")
        self.results_table_model.addColumn("Method")
        self.results_table_model.addColumn("URL")
        self.results_table_model.addColumn("Status Code")
        self.results_table_model.addColumn("Response Length")
        self.results_table_model.addColumn("Notes")
        self.results_table = JTable(self.results_table_model)
        self.results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.results_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self.results_table.getSelectionModel().addListSelectionListener(ResultsTableSelectionHandler(self))
        results_scroll = JScrollPane(self.results_table)
        results_scroll.setPreferredSize(Dimension(700, 300))
        test_section.add(results_scroll, BorderLayout.CENTER)
        self.status_area = JTextArea(3, 50)
        self.status_area.setEditable(False)
        status_scroll = JScrollPane(self.status_area)
        status_scroll.setBorder(BorderFactory.createTitledBorder("Status"))
        test_section.add(status_scroll, BorderLayout.SOUTH)
        bottom_split.setLeftComponent(test_section)
        viewer_panel = JPanel(BorderLayout())
        viewer_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        viewer_split.setResizeWeight(0.5)
        request_panel = JPanel(BorderLayout())
        request_panel.setBorder(BorderFactory.createTitledBorder("Request"))
        self.request_editor = self.callbacks.createMessageEditor(self, False)
        request_panel.add(self.request_editor.getComponent(), BorderLayout.CENTER)
        viewer_split.setTopComponent(request_panel)
        response_panel = JPanel(BorderLayout())
        response_panel.setBorder(BorderFactory.createTitledBorder("Response"))
        self.response_editor = self.callbacks.createMessageEditor(self, False)
        response_panel.add(self.response_editor.getComponent(), BorderLayout.CENTER)
        viewer_split.setBottomComponent(response_panel)
        viewer_panel.add(viewer_split, BorderLayout.CENTER)
        bottom_split.setRightComponent(viewer_panel)
        bottom_panel.add(bottom_split, BorderLayout.CENTER)
        main_split.setBottomComponent(bottom_panel)
        self.panel.add(main_split, BorderLayout.CENTER)
        self.role_pattern_panels = []

    def _isStaticResource(self, request_response):
        try:
            service = request_response.getHttpService()
            request_info = self.helpers.analyzeRequest(service, request_response.getRequest())
            url = request_info.getUrl()
            path = url.getPath().lower() if url.getPath() else ""
            if self.skip_js_checkbox.isSelected():
                if path.endswith('.js') or '/js/' in path:
                    return True
            if self.skip_css_checkbox.isSelected():
                if path.endswith('.css') or '/css/' in path:
                    return True
            if self.skip_images_checkbox.isSelected():
                img_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp']
                if any(path.endswith(ext) for ext in img_extensions) or '/images/' in path or '/img/' in path:
                    return True
            if self.skip_fonts_checkbox.isSelected():
                font_extensions = ['.woff', '.woff2', '.ttf', '.eot', '.otf']
                if any(path.endswith(ext) for ext in font_extensions) or '/fonts/' in path:
                    return True
            if self.skip_media_checkbox.isSelected():
                media_extensions = ['.pdf', '.zip', '.mp4', '.mp3', '.avi', '.mov']
                static_paths = ['/static/', '/assets/', '/media/', '/uploads/', '/files/']
                if any(path.endswith(ext) for ext in media_extensions) or any(static_path in path for static_path in static_paths):
                    return True
            return False
        except:
            return False
        
    def createPatternPair(self, index):
        pair_panel = JPanel(GridBagLayout())
        pair_panel.setBorder(BorderFactory.createTitledBorder("Regex #%d" % (index + 1)))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 3, 3, 3)
        gbc.anchor = GridBagConstraints.WEST
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 4
        enable_checkbox = JCheckBox("Enable this pattern", True)
        pair_panel.add(enable_checkbox, gbc)
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1
        pair_panel.add(JLabel("Find (regex):"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        find_field = JTextField("", 35)
        pair_panel.add(find_field, gbc)
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        pair_panel.add(JLabel("Replace with:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        replace_field = JTextField("", 35)
        pair_panel.add(replace_field, gbc)
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.fill = GridBagConstraints.HORIZONTAL
        pair_data = {
            'panel': pair_panel,
            'enabled': enable_checkbox,
            'find_field': find_field,
            'replace_field': replace_field
        }
        self.role_pattern_panels.append(pair_data)
        main_gbc = GridBagConstraints()
        main_gbc.gridx = 0; main_gbc.gridy = len(self.role_pattern_panels) - 1
        main_gbc.fill = GridBagConstraints.HORIZONTAL; main_gbc.weightx = 1.0
        main_gbc.insets = Insets(5, 5, 5, 5)
        self.main_patterns_panel.add(pair_panel, main_gbc)
        self.panel.revalidate()
        self.panel.repaint()

    def clearPatternPanels(self):
        self.main_patterns_panel.removeAll()
        self.role_pattern_panels = []
        self.panel.revalidate()
        self.panel.repaint()

    def loadRoleDetails(self):
        selected_role = str(self.role_combo.getSelectedItem()) if self.role_combo.getSelectedItem() else None
        self.clearPatternPanels()
        if selected_role and selected_role in self.roles:
            role_data = self.roles[selected_role]
            self.role_name_field.setText(selected_role)
            for i, pattern in enumerate(role_data.get("regex_pairs", [])):
                self.createPatternPair(i)
                if i < len(self.role_pattern_panels):
                    self.role_pattern_panels[i]['enabled'].setSelected(pattern.get("enabled", True))
                    self.role_pattern_panels[i]['find_field'].setText(pattern.get("find", ""))
                    self.role_pattern_panels[i]['replace_field'].setText(pattern.get("replace", ""))
        else:
            self.role_name_field.setText("")

    def saveRoleDetails(self):
        role_name = self.role_name_field.getText().strip()
        if not role_name:
            self.addStatus("Error: Role name cannot be empty")
            return
        regex_pairs = []
        for pattern_data in self.role_pattern_panels:
            find_text = pattern_data['find_field'].getText().strip()
            replace_text = pattern_data['replace_field'].getText().strip()
            if find_text:
                regex_pairs.append({
                    "enabled": pattern_data['enabled'].isSelected(),
                    "find": find_text,
                    "replace": replace_text
                })
        old_name = str(self.role_combo.getSelectedItem()) if self.role_combo.getSelectedItem() else None
        role_data = {
            "regex_pairs": regex_pairs,
        }
        if old_name and old_name != role_name and old_name in self.roles:
            del self.roles[old_name]
            self.role_combo.removeItem(old_name)
        self.roles[role_name] = role_data
        if role_name not in [str(self.role_combo.getItemAt(i)) for i in range(self.role_combo.getItemCount())]:
            self.role_combo.addItem(role_name)
        self.role_combo.setSelectedItem(role_name)

    def refreshTargets(self):
        try:
            target_map = self.callbacks.getSiteMap(None)
            if not target_map:
                self.addStatus("No target history found")
                return
            self.target_combo.removeAllItems()
            targets = set()
            for item in target_map:
                try:
                    service = item.getHttpService()
                    port_str = ""
                    if service.getPort() != 80 and service.getPort() != 443:
                        port_str = ":%d" % service.getPort()
                    target = "%s://%s%s" % (service.getProtocol(), service.getHost(), port_str)
                    targets.add(target)
                except:
                    continue
            sorted_targets = sorted(list(targets))
            for target in sorted_targets:
                self.target_combo.addItem(target)
            if sorted_targets:
                self.target_combo.insertItemAt("All Targets", 0)
                self.target_combo.setSelectedIndex(0)
            else:
                self.addStatus("No valid targets found in history")
        except Exception as e:
            self.addStatus("Error refreshing targets: %s" % str(e))

    def updateScopeFromTarget(self):
        try:
            selected_target = str(self.target_combo.getSelectedItem()) if self.target_combo.getSelectedItem() else None
            if not selected_target or selected_target == "All Targets":
                targets = []
                for i in range(1, self.target_combo.getItemCount()):
                    targets.append(str(self.target_combo.getItemAt(i)))
                if targets:
                    escaped_targets = [re.escape(target) for target in targets]
                    scope_pattern = "(%s)/.*" % "|".join(escaped_targets)
                    self.scope_field.setText(scope_pattern)
            else:
                escaped_target = re.escape(selected_target)
                scope_pattern = "%s/.*" % escaped_target
                self.scope_field.setText(scope_pattern)
        except Exception as e:
            self.addStatus("Error updating scope from target: %s" % str(e))

    def actionPerformed(self, event):
        source = event.getSource()
        if source == self.add_role_button:
            self.addNewRole()
        elif source == self.delete_role_button:
            self.deleteRole()
        elif source == self.role_combo:
            self.loadRoleDetails()
        elif source == self.add_pattern_button:
            self.createPatternPair(len(self.role_pattern_panels))
        elif source == self.save_role_button:
            self.saveRoleDetails()
        elif source == self.test_history_button:
            self.testProxyHistory()
        elif source == self.test_target_button:
            self.testSiteMap()
        elif source == self.stop_test_button:
            self.stopTesting()
        elif source == self.clear_results_button:
            self.clearResults()
        elif source == self.export_csv_button:
            self.exportCSV()
        elif source == self.export_html_button:
            self.exportHTML()
        elif source == self.save_state_button:
            self.saveState()
        elif source == self.load_state_button:
            self.loadState()
        elif source == self.refresh_targets_button:
            self.refreshTargets()
        elif source == self.target_combo:
            self.updateScopeFromTarget()
        elif source == self.scope_method_combo:
            self.updateScopeMethod()

    def updateScopeMethod(self):
        method = str(self.scope_method_combo.getSelectedItem())
        if method == "Target History":
            self.refresh_targets_button.setEnabled(True)
            self.target_combo.setEnabled(True)
            self.scope_field.setToolTipText("Select a target from dropdown")
            if self.target_combo.getItemCount() == 0:
                self.refreshTargets()
        else:
            self.refresh_targets_button.setEnabled(False)
            self.target_combo.setEnabled(False)
            self.scope_field.setToolTipText("Enter custom regex pattern")

    def addNewRole(self):
        self.role_combo.setSelectedItem(None)
        self.clearPatternPanels()
        self.role_name_field.setText("")
        self.createPatternPair(0)

    def deleteRole(self):
        selected_role = str(self.role_combo.getSelectedItem()) if self.role_combo.getSelectedItem() else None
        if selected_role and selected_role in self.roles:
            del self.roles[selected_role]
            self.role_combo.removeItem(selected_role)
            self.clearPatternPanels()
            self.role_name_field.setText("")
        else:
            self.addStatus("No role selected to delete")

    def saveState(self):
        try:
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save Permiter State")
            default_name = "permiter_state_%s.json" % time.strftime("%Y%m%d_%H%M%S")
            file_chooser.setSelectedFile(java.io.File(default_name))
            json_filter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
            file_chooser.setFileFilter(json_filter)
            result = file_chooser.showSaveDialog(self.panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                if not file_path.lower().endswith('.json'):
                    file_path += '.json'
                state_data = {
                    "version": "1.0",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "scope_method": str(self.scope_method_combo.getSelectedItem()),
                    "scope_pattern": self.scope_field.getText(),
                    "exclude_endpoints": self.exclude_field.getText(),
                    "request_delay": self.delay_spinner.getValue(),
                    "include_unauth": self.test_unauth_checkbox.isSelected(),
                    "roles": self.roles,
                    "skip_js": self.skip_js_checkbox.isSelected(),
                    "skip_css": self.skip_css_checkbox.isSelected(),
                    "skip_images": self.skip_images_checkbox.isSelected(),
                    "skip_fonts": self.skip_fonts_checkbox.isSelected(),
                    "skip_media": self.skip_media_checkbox.isSelected(),
                    "use_entire_history": self.use_entire_history_checkbox.isSelected()
                }
                def _do_save(path, data):
                    try:
                        with open(path, 'w') as f:
                            f.write(json.dumps(data, indent=2))
                        self.addStatus("State saved to %s" % path)
                    except Exception as e:
                        self.addStatus("Error saving state: %s" % str(e))
                thread = threading.Thread(target=_do_save, args=(file_path, state_data))
                thread.daemon = True
                thread.start()
        except Exception as e:
            self.addStatus("Error saving state: %s" % str(e))

    def loadState(self):
        try:
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Load Permiter State")
            json_filter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
            file_chooser.setFileFilter(json_filter)
            result = file_chooser.showOpenDialog(self.panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                def _do_load(path):
                    try:
                        with open(path, 'r') as f:
                            state_data = json.loads(f.read())
                        from javax.swing import SwingUtilities
                        def _apply():
                            if "scope_method" in state_data:
                                self.scope_method_combo.setSelectedItem(state_data["scope_method"])
                            if "scope_pattern" in state_data:
                                self.scope_field.setText(state_data["scope_pattern"])
                            if "exclude_endpoints" in state_data:
                                self.exclude_field.setText(state_data["exclude_endpoints"])
                            if "request_delay" in state_data:
                                self.delay_spinner.setValue(state_data["request_delay"])
                            if "include_unauth" in state_data:
                                self.test_unauth_checkbox.setSelected(state_data["include_unauth"])
                            if "skip_js" in state_data:
                                self.skip_js_checkbox.setSelected(state_data["skip_js"])
                            if "skip_css" in state_data:
                                self.skip_css_checkbox.setSelected(state_data["skip_css"])
                            if "skip_images" in state_data:
                                self.skip_images_checkbox.setSelected(state_data["skip_images"])
                            if "skip_fonts" in state_data:
                                self.skip_fonts_checkbox.setSelected(state_data["skip_fonts"])
                            if "skip_media" in state_data:
                                self.skip_media_checkbox.setSelected(state_data["skip_media"])
                            if "roles" in state_data:
                                self.roles = state_data["roles"]
                                self.role_combo.removeAllItems()
                                for role_name in self.roles.keys():
                                    self.role_combo.addItem(role_name)
                                if self.role_combo.getItemCount() > 0:
                                    self.role_combo.setSelectedIndex(0)
                                    self.loadRoleDetails()
                            if "use_entire_history" in state_data:
                                self.use_entire_history_checkbox.setSelected(state_data["use_entire_history"])
                            self.addStatus("State loaded from %s" % path)
                        SwingUtilities.invokeLater(_apply)
                    except Exception as e:
                        self.addStatus("Error loading state: %s" % str(e))
                thread = threading.Thread(target=_do_load, args=(file_path,))
                thread.daemon = True
                thread.start()
        except Exception as e:
            self.addStatus("Error loading state: %s" % str(e))

    def exportCSV(self):
        try:
            if not self.test_results:
                return
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Export Results to CSV")
            default_name = "permiter_results_%s.csv" % time.strftime("%Y%m%d_%H%M%S")
            file_chooser.setSelectedFile(java.io.File(default_name))
            csv_filter = FileNameExtensionFilter("CSV files (*.csv)", ["csv"])
            file_chooser.setFileFilter(csv_filter)
            result = file_chooser.showSaveDialog(self.panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                if not file_path.lower().endswith('.csv'):
                    file_path += '.csv'
                results_snapshot = list(self.test_results)
                def _do_export_csv(path, results):
                    try:
                        with open(path, 'w') as f:
                            f.write("Role,Method,URL,Status Code,Response Length,Notes\n")
                            for result in results:
                                row = [
                                    '"%s"' % result["role"].replace('"', '""'),
                                    result["method"],
                                    '"%s"' % result["url"].replace('"', '""'),
                                    result["status"],
                                    result["response_length"],
                                    '"%s"' % result["notes"].replace('"', '""')
                                ]
                                f.write(",".join(row) + "\n")
                        self.addStatus("CSV exported to %s" % path)
                    except Exception as e:
                        self.addStatus("Error exporting CSV: %s" % str(e))
                thread = threading.Thread(target=_do_export_csv, args=(file_path, results_snapshot))
                thread.daemon = True
                thread.start()
        except Exception as e:
            self.addStatus("Error exporting CSV: %s" % str(e))

    def exportHTML(self):
        try:
            if not self.test_results:
                return
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Export Results to HTML")
            default_name = "permiter_results_%s.html" % time.strftime("%Y%m%d_%H%M%S")
            file_chooser.setSelectedFile(java.io.File(default_name))
            html_filter = FileNameExtensionFilter("HTML files (*.html)", ["html"])
            file_chooser.setFileFilter(html_filter)
            result = file_chooser.showSaveDialog(self.panel)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                if not file_path.lower().endswith('.html'):
                    file_path += '.html'
                html_content = self._generateHTMLReport()
                def _do_export_html(path, content):
                    try:
                        with open(path, 'w') as f:
                            f.write(content)
                        self.addStatus("HTML exported to %s" % path)
                    except Exception as e:
                        self.addStatus("Error exporting HTML: %s" % str(e))
                thread = threading.Thread(target=_do_export_html, args=(file_path, html_content))
                thread.daemon = True
                thread.start()
        except Exception as e:
            self.addStatus("Error exporting HTML: %s" % str(e))

    def _generateHTMLReport(self):
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            status_counts = {}
            role_counts = {}
            for result in self.test_results:
                status = result["status"]
                role = result["role"]
                status_counts[status] = status_counts.get(status, 0) + 1
                role_counts[role] = role_counts.get(role, 0) + 1
            html = """<!DOCTYPE html>
    <html>
    <head>
        <title>Permiter Results - {timestamp}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; word-wrap: break-word; }}
            table {{ border-collapse: collapse; width: 100%; font-size: 12px; table-layout: fixed; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; }}
            .url {{ font-family: monospace; font-size: 11px; max-width: 300px; word-break: break-all; }}
            .success {{ background-color: #e6ffe6; }}
            .error {{ background-color: #ffe6e6; }}
            .warning {{ background-color: #ffffe6; }}
            .toggle-btn {{ 
                background-color: #007cba; 
                color: white; 
                border: none; 
                padding: 4px 8px; 
                cursor: pointer; 
                border-radius: 3px;
                font-size: 11px;
                margin: 2px;
            }}
            .toggle-btn:hover {{ background-color: #005a8a; }}
            .req-resp-container {{ 
                display: none; 
                margin-top: 10px; 
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }}
            .req-resp-header {{ 
                background-color: #e9ecef; 
                padding: 8px; 
                font-weight: bold; 
                border-bottom: 1px solid #dee2e6;
            }}
            .req-resp-content {{ 
                padding: 10px; 
                font-family: monospace; 
                font-size: 11px; 
                white-space: pre-wrap; 
                max-height: 400px; 
                overflow-y: auto;
                background-color: #ffffff;
            }}
        </style>
        <script>
            function toggleReqResp(id) {{
                var container = document.getElementById(id);
                var btn = document.getElementById('btn_' + id);
                if (container.style.display === 'none' || container.style.display === '') {{
                    container.style.display = 'block';
                    btn.innerHTML = 'Hide Request/Response';
                }} else {{
                    container.style.display = 'none';
                    btn.innerHTML = 'Show Request/Response';
                }}
            }}
        </script>
    </head>
    <body>
        <div class="header">
            <h1>Permiter Results</h1>
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Scope:</strong> {scope}</p>
            <p><strong>Excluded Endpoints:</strong> {excluded}</p>
            <p><strong>Total Tests:</strong> {total}</p>
        </div>
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Status Codes:</strong></p>
            <ul>
    """.format(
                timestamp=timestamp,
                scope=self.scope_field.getText(),
                excluded=self.exclude_field.getText(),
                total=len(self.test_results)
            )
            for status, count in sorted(status_counts.items()):
                html += "        <li>HTTP {status}: {count} tests</li>\n".format(
                    status=status, count=count)
            html += """    </ul>
            <p><strong>Roles Tested:</strong></p>
            <ul>
    """
            for role, count in sorted(role_counts.items()):
                html += "        <li>{role}: {count} tests</li>\n".format(
                    role=role, count=count)
            html += """    </ul>
        </div>
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Role</th>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Response Length</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
    """
            for i, result in enumerate(self.test_results):
                status_class = "success" if result["status"] == "200" else (
                    "error" if result["status"] in ["401", "403"] else "warning")
                request_content = ""
                response_content = ""
                try:
                    if "request" in result:
                        request_str = self.helpers.bytesToString(result["request"])
                        request_content = ''.join(c if ord(c) < 128 else '?' for c in request_str)
                        request_content = request_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                except:
                    request_content = "Error displaying request"
                try:
                    if "response" in result:
                        response_str = self.helpers.bytesToString(result["response"])
                        response_content = ''.join(c if ord(c) < 128 else '?' for c in response_str)
                        response_content = response_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                except:
                    response_content = "Error displaying response"
                html += """        <tr>
                    <td>{role}</td>
                    <td>{method}</td>
                    <td class="url">{url}</td>
                    <td class="{status_class}">{status}</td>
                    <td>{response_length}</td>
                    <td class="notes">
                        {notes}
                        <br><button class="toggle-btn" id="btn_reqresp_{i}" onclick="toggleReqResp('reqresp_{i}')">Show Request/Response</button>
                        <div class="req-resp-container" id="reqresp_{i}">
                            <div class="req-resp-header">Request</div>
                            <div class="req-resp-content">{request_content}</div>
                            <div class="req-resp-header">Response</div>
                            <div class="req-resp-content">{response_content}</div>
                        </div>
                    </td>
                </tr>
    """.format(
                    role=result["role"],
                    method=result["method"],
                    url=result["url"],
                    status_class=status_class,
                    status=result["status"],
                    response_length=result["response_length"],
                    notes=result["notes"],
                    i=i,
                    request_content=request_content,
                    response_content=response_content
                )
            html += """    </tbody>
        </table>
        <div class="header" style="margin-top: 30px;">
            <p><em>Report generated by Permiter</em></p>
        </div>
    </body>
    </html>"""
            return html
        except Exception as e:
            self.addStatus("Error generating HTML report: %s" % str(e))
            return "<html><body><h1>Error generating report</h1></body></html>"
        
    def testProxyHistory(self):
        if not self.roles:
            return
        self.startTesting("Proxy History")

    def testSiteMap(self):
        if not self.roles:
            return
        self.startTesting("Site Map")

    def startTesting(self, test_type):
        if self.current_testing_thread and self.current_testing_thread.isAlive():
            self.addStatus("Testing already in progress")
            return
        self.stop_testing = False
        self.tested_urls.clear()
        self.test_history_button.setEnabled(False)
        self.test_target_button.setEnabled(False)
        self.stop_test_button.setEnabled(True)
        if test_type == "Proxy History":
            self.current_testing_thread = threading.Thread(target=self._testProxyHistoryBackground)
        else:
            self.current_testing_thread = threading.Thread(target=self._testSiteMapBackground)
        self.current_testing_thread.daemon = True
        self.current_testing_thread.start()

    def stopTesting(self):
        self.stop_testing = True
        self.test_history_button.setEnabled(True)
        self.test_target_button.setEnabled(True)
        self.stop_test_button.setEnabled(False)

    def _testProxyHistoryBackground(self):
        try:
            proxy_history = self.callbacks.getProxyHistory()
            scope_pattern = self.scope_field.getText().strip()
            tested_count = 0
            for request_response in proxy_history:
                if self.stop_testing:
                    break
                if self._isInScope(request_response, scope_pattern) and not self._isExcluded(request_response):
                    if self._testRequestWithAllRoles(request_response, "Proxy History"):
                        tested_count += 1
        except Exception as e:
            self.addStatus("Error in proxy history testing: %s" % str(e))
        finally:
            self.stopTesting()

    def _testSiteMapBackground(self):
        try:
            site_map = self.callbacks.getSiteMap(None)
            scope_pattern = self.scope_field.getText().strip()
            tested_count = 0
            for request_response in site_map:
                if self.stop_testing:
                    break
                if self._isInScope(request_response, scope_pattern) and not self._isExcluded(request_response):
                    if self._testRequestWithAllRoles(request_response, "Site Map"):
                        tested_count += 1
        except Exception as e:
            self.addStatus("Error in site map testing: %s" % str(e))
        finally:
            self.stopTesting()

    def _isInScope(self, request_response, scope_pattern):
        if not scope_pattern:
            return True
        try:
            service = request_response.getHttpService()
            request_info = self.helpers.analyzeRequest(service, request_response.getRequest())
            port_str = ""
            if service.getPort() != 80 and service.getPort() != 443:
                port_str = ":%d" % service.getPort()
            url = "%s://%s%s%s" % (service.getProtocol(), service.getHost(), port_str, request_info.getUrl().getPath())
            return re.match(scope_pattern, url) is not None
        except:
            return False
        
    def _isExcluded(self, request_response):
        exclude_patterns = self.exclude_field.getText().strip()
        if not exclude_patterns:
            return False
        try:
            service = request_response.getHttpService()
            request_info = self.helpers.analyzeRequest(service, request_response.getRequest())
            path = request_info.getUrl().getPath()
            for pattern in exclude_patterns.split(','):
                pattern = pattern.strip()
                if not pattern:
                    continue
                try:
                    if re.search(pattern, path, re.IGNORECASE):
                        return True
                except:
                    if pattern.lower() in path.lower():
                        return True
            return False
        except:
            return False
        
    def _testRequestWithAllRoles(self, original_request_response, test_type):
        if self._isStaticResource(original_request_response):
            return False
        try:
            original_request = original_request_response.getRequest()
            service = original_request_response.getHttpService()
            request_info = self.helpers.analyzeRequest(service, original_request)
            port_str = ""
            if service.getPort() != 80 and service.getPort() != 443:
                port_str = ":%d" % service.getPort()
            url = "%s://%s%s%s" % (service.getProtocol(), service.getHost(), port_str, request_info.getUrl().getPath())
            method = request_info.getMethod()
            url_key = "%s %s" % (method, url)
            if not self.use_entire_history_checkbox.isSelected() and url_key in self.tested_urls:
                return False
            if not self.use_entire_history_checkbox.isSelected():
                self.tested_urls.add(url_key)
            test_threads = []
            for role_name, role_data in self.roles.items():
                if self.stop_testing:
                    break
                thread = threading.Thread(target=self._testSingleRole, args=(
                    original_request_response, test_type, role_name, role_data, url, method, service
                ))
                thread.daemon = True
                test_threads.append(thread)
                thread.start()
            if self.test_unauth_checkbox.isSelected():
                thread = threading.Thread(target=self._testUnauthenticated, args=(
                    original_request_response, test_type, url, method, service
                ))
                thread.daemon = True
                test_threads.append(thread)
                thread.start()
            for thread in test_threads:
                thread.join()
            return True
        except Exception as e:
            self.addStatus("Error in _testRequestWithAllRoles: %s" % str(e))
            return False
        
    def _testSingleRole(self, original_request_response, test_type, role_name, role_data, url, method, service):
        try:
            if self.stop_testing:
                return
            original_request = original_request_response.getRequest()
            test_description = self._getTestDescription(role_name, role_data, service.getPort())
            modified_request = self._applyRoleToRequest(original_request, role_data)
            if modified_request:
                try:
                    response = self.callbacks.makeHttpRequest(service, modified_request)
                    if response and response.getResponse():
                        response_info = self.helpers.analyzeResponse(response.getResponse())
                        status_code = response_info.getStatusCode()
                        response_length = len(response.getResponse()) 
                        notes = self._analyzeResponse(status_code, original_request_response, response)
                        with self.test_lock:
                            result = {
                                "role": role_name,
                                "method": method,
                                "url": url,
                                "status": str(status_code),
                                "response_length": str(response_length),
                                "notes": notes,
                                "request": modified_request,
                                "response": response.getResponse(),
                                "service": service
                            }
                            self.test_results.append(result)
                            self._updateResultsTable()
                    else:
                        with self.test_lock:
                            result = {
                                "role": role_name,
                                "method": method,
                                "url": url,
                                "status": "NO_RESPONSE",
                                "response_length": "0",
                                "notes": "Request failed - no response received",
                                "request": modified_request,
                                "response": None,
                                "service": service
                            }
                            self.test_results.append(result)
                            self._updateResultsTable()
                    delay_ms = self.delay_spinner.getValue()
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                except Exception as e:
                    with self.test_lock:
                        result = {
                            "role": role_name,
                            "method": method,
                            "url": url,
                            "status": "ERROR",
                            "response_length": "0",
                            "notes": "Request error: %s" % str(e),
                            "request": modified_request,
                            "response": None,
                            "service": service
                        }
                        self.test_results.append(result)
                        self._updateResultsTable()
                    self.addStatus("Error testing %s with %s: %s" % (url, role_name, str(e)))
        except Exception as e:
            self.addStatus("Error in _testSingleRole for %s: %s" % (role_name, str(e)))

    def _testUnauthenticated(self, original_request_response, test_type, url, method, service):
        try:
            if self.stop_testing:
                return
            original_request = original_request_response.getRequest()
            unauthenticated_request = self._removeAuthPatterns(original_request)
            if unauthenticated_request:
                try:
                    response = self.callbacks.makeHttpRequest(service, unauthenticated_request)
                    if response and response.getResponse():
                        response_info = self.helpers.analyzeResponse(response.getResponse())
                        status_code = response_info.getStatusCode()
                        response_length = len(response.getResponse())
                        notes = self._analyzeResponse(status_code, original_request_response, response)
                        with self.test_lock:
                            result = {
                                "role": "UNAUTHENTICATED",
                                "method": method,
                                "url": url,
                                "status": str(status_code),
                                "response_length": str(response_length),
                                "notes": notes,
                                "request": unauthenticated_request,
                                "response": response.getResponse(),
                                "service": service
                            }
                            self.test_results.append(result)
                            self._updateResultsTable()
                    else:
                        with self.test_lock:
                            result = {
                                "role": "UNAUTHENTICATED",
                                "method": method,
                                "url": url,
                                "status": "NO_RESPONSE",
                                "response_length": "0",
                                "notes": "Request failed - no response received",
                                "request": unauthenticated_request,
                                "response": None,
                                "service": service
                            }
                            self.test_results.append(result)
                            self._updateResultsTable()
                    delay_ms = self.delay_spinner.getValue()
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                except Exception as e:
                    with self.test_lock:
                        result = {
                            "role": "UNAUTHENTICATED", 
                            "method": method,
                            "url": url,
                            "status": "ERROR",
                            "response_length": "0",
                            "notes": "Request error: %s" % str(e),
                            "request": unauthenticated_request,
                            "response": None,
                            "service": service
                        }
                        self.test_results.append(result)
                        self._updateResultsTable()
                    self.addStatus("Error testing %s unauthenticated: %s" % (url, str(e)))
        except Exception as e:
            self.addStatus("Error in _testUnauthenticated: %s" % str(e))

    def _removeAuthPatterns(self, original_request):
        try:
            request_str = self.helpers.bytesToString(original_request)
            lines = request_str.split('\n')
            auth_headers = ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 
                        'x-access-token', 'x-csrf-token', 'x-xsrf-token']
            cleaned_lines = []
            in_headers = True
            for line in lines:
                if in_headers and line.strip() == '':
                    in_headers = False
                    cleaned_lines.append(line)
                    continue
                if in_headers:
                    should_remove = False
                    line_lower = line.lower().strip()
                    for header in auth_headers:
                        if line_lower.startswith(header + ':'):
                            should_remove = True
                            break
                    if not should_remove:
                        cleaned_lines.append(line)
                else:
                    cleaned_lines.append(line)
            modified_request_str = '\n'.join(cleaned_lines)            
            modified_request_str = re.sub(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', '', modified_request_str, flags=re.IGNORECASE)
            modified_request_str = re.sub(r'Basic\s+[A-Za-z0-9+/]+=*', '', modified_request_str, flags=re.IGNORECASE)
            return self.helpers.stringToBytes(modified_request_str)
        except Exception as e:
            self.addStatus("Error removing auth patterns: %s" % str(e))
            return original_request
        
    def _getTestDescription(self, role_name, role_data, actual_port):
            return "Standard Test"
    
    def _applyRoleToRequest(self, original_request, role_data):
        try:
            request_str = self.helpers.bytesToString(original_request)
            modified_request_str = request_str
            for pattern in role_data.get("regex_pairs", []):
                if not pattern.get("enabled", True):
                    continue
                find_pattern = pattern["find"]
                replacement = pattern["replace"]
                try:
                    modified_request_str = re.sub(find_pattern, replacement, modified_request_str, flags=re.IGNORECASE | re.MULTILINE)
                except Exception as e:
                    self.addStatus("Regex error in pattern '%s': %s" % (find_pattern, str(e)))
                    continue
            return self.helpers.stringToBytes(modified_request_str)
        except Exception as e:
            self.addStatus("Error applying role patterns: %s" % str(e))
            return None
        
    def _analyzeResponse(self, status_code, original_response, test_response):
        notes = []
        if status_code == 200:
            notes.append("SUCCESS")
        elif status_code == 401:
            notes.append("UNAUTHORIZED")
        elif status_code == 403:
            notes.append("FORBIDDEN")
        elif status_code == 404:
            notes.append("NOT_FOUND")
        elif status_code >= 500:
            notes.append("SERVER_ERROR")
        else:
            notes.append("HTTP_%d" % status_code)
        try:
            if original_response.getResponse():
                original_info = self.helpers.analyzeResponse(original_response.getResponse())
                original_status = original_info.getStatusCode()
                if status_code != original_status:
                    notes.append("DIFF_FROM_ORIG_%d" % original_status)
        except:
            pass
        return " | ".join(notes)
    
    def _updateResultsTable(self):
        while self.results_table_model.getRowCount() > 0:
            self.results_table_model.removeRow(0)
        for result in self.test_results:
            row = [
                result["role"],
                result["method"],
                result["url"],
                result["status"],
                result["response_length"],
                result["notes"]
            ]
            self.results_table_model.addRow(row)

    def showRequestResponse(self, result):
        try:
            if self.current_testing_thread and self.current_testing_thread.isAlive():
                return
            if result and "request" in result and "response" in result:
                self.current_request_response = TestRequestResponse(
                    result["request"], 
                    result["response"], 
                    result["service"]
                )
                self.request_editor.setMessage(result["request"], True)
                self.response_editor.setMessage(result["response"], False)
            else:
                self.request_editor.setMessage(None, True)
                self.response_editor.setMessage(None, False)
        except Exception as e:
            self.addStatus("Error displaying request/response: %s" % str(e))

    def clearResults(self):
        with self.test_lock:
            self.test_results = []
            self.tested_urls.clear()
            self._updateResultsTable()
            self.request_editor.setMessage(None, True)
            self.response_editor.setMessage(None, False)
            self.current_request_response = None

    def addStatus(self, message):
        current_text = self.status_area.getText()
        timestamp = time.strftime("%H:%M:%S")
        new_message = "[%s] %s" % (timestamp, message)
        lines = current_text.split('\n') if current_text else []
        if len(lines) > 50:
            lines = lines[:25]
        new_text = new_message + '\n' + '\n'.join(lines)
        self.status_area.setText(new_text)
        print(new_message)

    def getTabCaption(self):
        return "Permiter"
    
    def getUiComponent(self):
        return self.panel
    
    def getHttpService(self):
        return self.current_request_response.getHttpService() if self.current_request_response else None
    
    def getRequest(self):
        return self.current_request_response.getRequest() if self.current_request_response else None
    
    def getResponse(self):
        return self.current_request_response.getResponse() if self.current_request_response else None
    
    def createMenuItems(self, invocation):
        menu_items = []
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        ]:
            menu_item = JMenuItem("Test Authorization with All Roles")
            menu_item.addActionListener(AuthTestMenuHandler(self, invocation))
            menu_items.append(menu_item)
        return menu_items
    
class TestRequestResponse:
    def __init__(self, request, response, service):
        self._request = request
        self._response = response
        self._service = service

    def getRequest(self):
        return self._request
    
    def getResponse(self):
        return self._response
    
    def getHttpService(self):
        return self._service
    
class ResultsTableSelectionHandler(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            selected_row = self.extender.results_table.getSelectedRow()
            if selected_row >= 0 and selected_row < len(self.extender.test_results):
                result = self.extender.test_results[selected_row]
                self.extender.showRequestResponse(result)

class CopyPatternHandler(ActionListener):
    def __init__(self, target_field, pattern_text):
        self.target_field = target_field
        self.pattern_text = pattern_text

    def actionPerformed(self, event):
        self.target_field.setText(self.pattern_text)

class AuthTestMenuHandler(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        selected_messages = self.invocation.getSelectedMessages()
        if selected_messages and len(selected_messages) > 0:
            def test_selected():
                try:
                    for request_response in selected_messages:
                        if not self.extender._isExcluded(request_response):
                            self.extender._testRequestWithAllRoles(request_response, "Manual Test")
                        else:
                            self.extender.addStatus("Skipping excluded endpoint")
                    self.extender.addStatus("Completed testing selected requests")
                except Exception as e:
                    self.extender.addStatus("Error testing selected requests: %s" % str(e))
            thread = threading.Thread(target=test_selected)
            thread.daemon = True
            thread.start()