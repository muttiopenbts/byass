'''
Taken from Burps custom logger example and extended.
Purpose: Scan repeater requests for {{tag}} and replace with output of custom
python function.


Author mkocbayi@gmail.com
'''
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JPanel;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import JButton;
from javax.swing import JTextField;
from javax.swing import JTextArea;
from javax.swing import JTree;
from javax.swing import JLabel;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import json
from urlparse import urlparse
import re
import copy


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    #
    # implement IBurpExtender
    #

    # Discovered hosts
    hosts_dic = {}

    log_columns = ['Tool','Host','Path + Query', 'Comment']

    # Use for starting point of request/response trace
    _filter_txt_field = ''

    _debug_textarea = ''
    _extension_name = 'PyJect'
    _stdout = None
    _stderr = None

    # regex for url searching
    _url_regex = r'(https?):\/\/(www\.)?[a-z0-9\.:].*?(?=(\s|[^\w\-.\/?&=%#]))'

    # Toggle extension start/stop use
    _ss_button = None

    # Cookie values that a related to the session
    cookies = {}
    # Search terms in cookie names
    cookie_keywords = 'session|password|customer|token|service'

    def refreshDebug(self, event):
        filter_string = self._filter_txt_field.getText()

        filtered_hosts = {}
        for k,urls in self.hosts_dic.iteritems():
            filtered_urls = []
            for url in urls:
                if filter_string in url:
                    filtered_urls += [url]

            filtered_hosts[k] = filtered_urls


        # Update debug textarea
        self._debug_textarea.text = 'Discovered hosts\n'
        self._debug_textarea.text += json.dumps(filtered_hosts, indent=4, sort_keys=True)

    def resetLogger(self, event):
        # clear fqdn textbox
        self._filter_txt_field.text = ''
        # Reset textarea displaying search tokens
        self._debug_textarea.text = ''
        self.tokens = {}
        self.hosts_dic = {}
        # Clear Table
        self._log = ArrayList()

    # Toggle Start/Stop logger
    def toggleSS(self, event):
        # Use to stop and start this extension
        if self._ss_button.getText() == 'Start':
            self._ss_button.setText('Stop')
        else:
            self._ss_button.setText('Start')

    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._stdout = PrintWriter(self._callbacks.getStdout(), True)
        self._stderr = PrintWriter(self._callbacks.getStderr(), True)

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(self._extension_name)

        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()

        self._main_tabs = JTabbedPane()

        #
        # Debug tab
        #

        refresh_debug_button = JButton('Refresh', actionPerformed=self.refreshDebug)
        # filter text box
        self._filter_txt_field = JTextField('',25)
        filter_txt_field_label = JLabel("Type text to filter found urls:")

        # debug output
        self._debug_textarea = JTextArea()
        self._debug_textarea.text = 'Debug output'
        self._debug_textarea.editable = True
        self._debug_textarea.wrapStyleWord = True
        self._debug_textarea.lineWrap = True
        self._debug_textarea.alignmentX = Component.LEFT_ALIGNMENT

        debug_display_pane = JScrollPane(self._debug_textarea)

        # Debug top pane
        debug_top_panel = JPanel()
        debug_top_panel.add(filter_txt_field_label)
        debug_top_panel.add(self._filter_txt_field)
        debug_top_panel.add(refresh_debug_button)
        debug_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, debug_top_panel, debug_display_pane)

        #
        # Logger tab
        #

        # Reset button
        reset_button = JButton('Reset', actionPerformed=self.resetLogger)

        # Start/Stop button
        self._ss_button = JButton('Start', actionPerformed=self.toggleSS)

        # table of log entries
        logTable = Table(self)
        log_table_pane = JScrollPane(logTable)

        logger_top_panel = JPanel()
        logger_top_panel.add(self._ss_button)
        logger_top_panel.add(reset_button)

        # Top pane
        top_splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, logger_top_panel, log_table_pane)

        # tabs with request/response viewers
        rr_tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        rr_tabs.addTab("Request", self._requestViewer.getComponent())
        rr_tabs.addTab("Response", self._responseViewer.getComponent())
        # Main pane
        self._logger_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_splitpane, rr_tabs)

        # customize our UI components
        self._main_tabs.addTab("Logs", self._logger_split_pane)
        self._main_tabs.addTab("Debug", debug_split_pane)

        callbacks.customizeUiComponent(self._main_tabs)
        callbacks.customizeUiComponent(self._debug_textarea)
        callbacks.customizeUiComponent(self._logger_split_pane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(log_table_pane)
        callbacks.customizeUiComponent(rr_tabs)
        callbacks.customizeUiComponent(logTable)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        return

    #
    # implement ITab
    #

    def getTabCaption(self):
        return self._extension_name


    def getUiComponent(self):
        return self._main_tabs

    #
    # implement IHttpListener
    #

    # Attempts to retrieve a json value from given key
    # Params
    # key: string       json key
    # body: string      json formatted string
    #
    # Returns
    # string            json value
    def getJsonValue(self, key, body):
        try:
            json_dict = json.loads(body) # becomes dict

            # Token identify is specific to my use case. Will use regex if need changes.
            token_name = key
            # Convert json keys to lower case before compare token_name
            found_token_list = [json_dict.get(x) for x in json_dict.keys() if token_name == x.lower()]

            if found_token_list:
                return str(found_token_list.pop())
        except Exception as e:
            self._stderr.println('Error: {}\nBody = {}\ngetJsonValue'.format(e,str(body)))

    def getHeaderFor(self, string_headers, header_name):
        # Attempts to retrieve header from burp http request headers string
        # Param string_headers = '[Origin: blah, Cookie: x=y]'
        # Param header_name = 'Origin'
        # Returns string 'Origin: blah'

        #self._stdout.println('getheaderfor: ' + header_name)

        try:
            pattern = header_name

            # Strip '[' and ']', then break up. Not perfect.
            split_headers = \
                string_headers[1:-1].split(', ')

            #self._stdout.println('getheaderfor stringh_headers: ->{}<-'.format(string_headers))

            found_header = [header_item for header_item in split_headers if re.match(pattern,header_item.lower())].pop()

            if found_header:
                return str(found_header)
        except Exception as e:
            self._stderr.println('Error: {}\nBody = {}\ngetHeaderFor'.format(e,str(string_headers)))

    # Attempts to retrieve a bearer token from a json response body
    def getBearerToken(self, body):
        return self.getJsonValue('bearertoken', body)

    # Attempts to retrieve a list of bearer tokens from a json response body
    # Params:
    # body: string_headers              string representation of json
    # Returns
    # [(json_key,json_value)]           List of Tuples
    def getBearerTokens(self, body):
        token_ids = ['bearertoken','bearer']

        return [(token_id,self.getJsonValue(token_id, body),) for token_id in token_ids]

    # Attempts to retrieve a sessionid token from a json response body
    def getSessionToken(self, body):
        return self.getJsonValue('sessionid', body)

    # Attempts to retrieve a list of session tokens from a json response body
    # Params:
    # body: string_headers              string representation of json
    # Returns
    # [(json_key,json_value)]           List of Tuples
    def getSessionTokens(self, body):
        # TODO: Change to regex search
        token_ids = ['sessionid','session','onetimepassword']

        return [(token_id,self.getJsonValue(token_id, body),) for token_id in token_ids]


    # Search blob of text for urls using regex and return a list
    # Params:
    # blob: text containing urls        String
    # Returns
    # ['https://a.com','host.com']      List of matched urls as generator
    def getRegexedUrls(self, blob):
        url_pattern = self._url_regex

        matches = re.finditer(url_pattern, blob, re.I)

        for url in matches:
            yield url.group()


    def getBody(self, rawMessage, parsedMessage):
        return self._helpers.bytesToString(rawMessage[parsedMessage.getBodyOffset():])


    ''' Taken from https://stackoverflow.com/questions/28288987/identify-the-file-extension-of-a-url
        Param:
        url_path: string        'host.domain.com/path/file.js'

        Returns:
        file extension: string  'js' or ''
    '''
    def getFileExtension(self, url_path):
        from os.path import splitext

        """Return the filename extension from url, or ''."""
        root, ext = splitext(url_path)
        if ext:
            return ext[1:]  # or ext[1:] if you don't want the leading '.'
        else:
            return ''


    '''
    Process http requests from Burp repeater.
    '''
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        url = ''
        mime_type = ''
        body = ''
        parsed_http_message = ''
        comment = ''

        # Don't do anything if ui button is set to stop
        if self._ss_button.getText() == 'Start':
            return

        # Do we have a request or response?
        if messageIsRequest and toolFlag == self.callbacks.TOOL_REPEATER :
            # Anaylyze http response
            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            url_parsed = urlparse(url)
            hostname = url_parsed.hostname
            path = url_parsed.path

            headers = parsed_http_message.getHeaders()

            query = url_parsed.query
            path_params = path

            if query: path_params += '?' + query

            file_extension = self.getFileExtension(path)

            # Do we have any persistant comments from related req/resp?
            if messageInfo.getComment():
                comment = messageInfo.getComment() + ' '

            # Apply our collected comments.
            messageInfo.setComment(comment)

    #
    # extend AbstractTableModel
    #

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return len(self.log_columns)

    def getColumnName(self, columnIndex):
        return self.log_columns[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._host
        if columnIndex == 2:
            return logEntry._url
        if columnIndex == 3:
            return logEntry._comment
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):

        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)

#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, host, comment):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._host = host
        self._comment = comment
