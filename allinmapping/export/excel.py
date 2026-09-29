# -*- coding: utf-8 -*-
"""Grid view -> .xls export."""
from javax.swing import JFileChooser, JOptionPane
from java.net import URL


class ExcelExportMixin(object):
    """Grid view -> .xls export."""

    def export_excel(self, event):
        if not self.target_roots: return
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Excel (XLS)")
        if chooser.showSaveDialog(self.mainPanel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith(".xls"): filepath += ".xls"

            excluded_exts = (
                '.gif', '.png', '.jpg', '.jpeg', '.svg', '.mp4', '.mp3', 
                '.ico', '.js', '.min.js', '.js.min', '.wav', '.mov', 
                '.ttf', '.woff', '.woff2', '.eot', '.otf', '.css', '.map'
            )

            try:
                xml_data = []
                xml_data.append('<?xml version="1.0"?>')
                xml_data.append('<?mso-application progid="Excel.Sheet"?>')
                xml_data.append('<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">')

                xml_data.append(""" <Styles>
  <Style ss:ID="HeaderL">
   <Font ss:Bold="1"/>
   <Interior ss:Color="#7DEFFF" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="HeaderR">
   <Font ss:Bold="1"/>
   <Interior ss:Color="#7DEFFF" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="NormL">
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="NormR">
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="TestL">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="TestR">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotL">
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotR">
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotTestL">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
  <Style ss:ID="BotTestR">
   <Interior ss:Color="#7DFF86" ss:Pattern="Solid"/>
   <Borders>
    <Border ss:Position="Right" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2"/>
    <Border ss:Position="Left" ss:LineStyle="Continuous" ss:Weight="1"/>
    <Border ss:Position="Top" ss:LineStyle="Continuous" ss:Weight="1"/>
   </Borders>
  </Style>
 </Styles>""")

                for host, root in self.target_roots.items():
                    sheet_name = host.replace("/", "").replace("\\", "").replace("?", "").replace("*", "").replace(":", "").replace("[", "").replace("]", "")
                    if len(sheet_name) > 31: sheet_name = sheet_name[:31]
                    if not sheet_name: sheet_name = "Unknown"

                    xml_data.append(' <Worksheet ss:Name="{}">'.format(sheet_name))
                    xml_data.append('  <Table>')

                    xml_data.append('   <Column ss:Width="60"/>') 
                    xml_data.append('   <Column ss:Width="300"/>') 
                    xml_data.append('   <Column ss:Width="100"/>')
                    xml_data.append('   <Column ss:Width="60"/>')  
                    xml_data.append('   <Column ss:Width="80"/>')  
                    xml_data.append('   <Column ss:Width="200"/>') 

                    xml_data.append('   <Row>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Method</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">URL</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Endpoint</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Tested</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderL"><Data ss:Type="String">Privilege</Data></Cell>')
                    xml_data.append('    <Cell ss:StyleID="HeaderR"><Data ss:Type="String">Notes</Data></Cell>')
                    xml_data.append('   </Row>')

                    rows_data = []

                    def traverse_excel(node):
                        has_http = (len(node.statuses) > 0) or (node.linked_request is not None) or (len(node.methods) > 0)
                        if node != root and not getattr(node, 'is_manual', False) and has_http:
                            full_url = node.get_full_url()
                            try:
                                u = URL(full_url)
                                endpoint = u.getPath()
                                if not endpoint: endpoint = "/"
                            except:
                                endpoint = node.text

                            if not any(endpoint.lower().endswith(ext) for ext in excluded_exts):
                                is_tested = True if node.status == "Tested" else False
                                ep_clean = endpoint.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                meths = ", ".join(node.methods)
                                nts = node.note.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                privs = getattr(node, 'privilege', "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                rows_data.append((meths, full_url, ep_clean, is_tested, privs, nts))

                        for child in node.children:
                            traverse_excel(child)

                    traverse_excel(root)

                    for idx, (meths, full_url, ep_clean, is_tested, privs, nts) in enumerate(rows_data):
                        is_last = (idx == len(rows_data) - 1)
                        if is_last:
                            style_L = "BotTestL" if is_tested else "BotL"
                            style_R = "BotTestR" if is_tested else "BotR"
                        else:
                            style_L = "TestL" if is_tested else "NormL"
                            style_R = "TestR" if is_tested else "NormR"

                        tested_str = "Yes" if is_tested else "No"

                        xml_data.append('   <Row>')
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, meths))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, full_url))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, ep_clean))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, tested_str))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_L, privs))
                        xml_data.append('    <Cell ss:StyleID="{}"><Data ss:Type="String">{}</Data></Cell>'.format(style_R, nts))
                        xml_data.append('   </Row>')

                    xml_data.append('  </Table>')
                    xml_data.append(' </Worksheet>')
                xml_data.append('</Workbook>')

                with open(filepath, 'w') as f:
                    f.write("\n".join(xml_data).encode("utf-8"))

                JOptionPane.showMessageDialog(self.mainPanel, "Excel Exported successfully!")
            except Exception as e:
                self.callbacks.printError("Failed to export Excel: " + str(e))
                JOptionPane.showMessageDialog(self.mainPanel, "Excel Export Failed: " + str(e))
