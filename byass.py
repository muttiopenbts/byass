'''
Taken from Burps custom logger example and extended.
Purpose: log http requests that maybe related through sessions-id, redirects, cors

TODO: Big cleanup, more use case testing.

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
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import json
from urlparse import urlparse
import re
import copy

from   javax.swing.tree  import DefaultMutableTreeNode
from   javax.swing.tree  import DefaultTreeModel
from   javax.swing.tree  import MutableTreeNode
from   javax.swing.tree  import TreePath
from   javax.swing.tree  import TreeSelectionModel

from   javax.swing.event import TreeModelListener
from   javax.swing.event import TreeSelectionListener


#-------------------------------------------------------------------------------
#    Name: DynamicTree.py
#    From: Swing for Jython
#      By: Robert A. (Bob) Gibson [rag]
# ISBN-13: 978-1-4824-0818-2 (paperback)
# ISBN-13: 978-1-4824-0817-5 (electronic)
# website: http://www.apress.com/978148420818
#    Role: Simple Jython Swing script showing how to monitor an editable tree
#   Usage: wsadmin -f DynamicTree.py
#            or
#          jython DynamicTree.py
# History:
#   date    who  ver   Comment
# --------  ---  ---  ----------
# 14/10/25  rag  0.0  New - ...
#-----------------
#-------------------------------------------------------------------------------
#  Name: myTreeModelListener
#  Role: personalized TreeModelListener class
#-------------------------------------------------------------------------------
class myTreeModelListener( TreeModelListener ) :

    #---------------------------------------------------------------------------
    # Name: getNode
    # Role: Common routine used to locate the affected node
    #---------------------------------------------------------------------------
    def getNode( self, event ) :
        try :
            parent = self.getParent( event )
            node = parent.getChildAt(
                event.getChildIndices()[ 0 ]
            )
        except :
            node = event.getSource().getRoot()
        return node

    #---------------------------------------------------------------------------
    # Name: getParent
    # Role: Common routine used to locate the parent of the affected node
    #---------------------------------------------------------------------------
    def getParent( self, event ) :
        try :
            #-------------------------------------------------------------------
            # Path to the parent of the modified TreeNode
            # Traverse the tree to locate the parent node
            #-------------------------------------------------------------------
            path = event.getTreePath().getPath()
            parent = path[ 0 ]         # Start with root node
            for node in path[ 1: ] :   # Get parent of changed node
                parent = parent.getChildAt(
                    parent.getIndex( node )
                )
        except :
            parent = None
        return parent

    #---------------------------------------------------------------------------
    # Name: treeNodesChanged
    # Role: Invoked when the monitored TreeMode instance event occurs
    #---------------------------------------------------------------------------
    def treeNodesChanged( self, event ) :
        node = self.getNode( event )
        print ' treeNodesChanged():', node.getUserObject()

    #---------------------------------------------------------------------------
    # Name: treeNodesInserted
    # Role: Invoked when the monitored TreeMode instance event occurs
    #---------------------------------------------------------------------------
    def treeNodesInserted( self, event ) :
        node = self.getNode( event )
        print 'treeNodesInserted():', node.getUserObject()

    #---------------------------------------------------------------------------
    # Name: treeNodesRemoved
    # Role: Invoked when the monitored TreeMode instance event occurs
    #---------------------------------------------------------------------------
    def treeNodesRemoved( self, event ) :
        print ' treeNodesRemoved(): child %d under "%s"' % (
            event.getChildIndices()[ 0 ],
            self.getParent( event )
        )

    #---------------------------------------------------------------------------
    # Name: treeStructureChanged
    # Role: Invoked when the monitored TreeMode instance event occurs
    #---------------------------------------------------------------------------
    def treeStructureChanged( self, event ) :
        print 'treeStructureChanged():'


#-------------------------------------------------------------------------------
#  Name: DynamicTree
#  Role: User application demonstrating the use of a TreeModelListener to
#        monitor changes to the tree
#-------------------------------------------------------------------------------
class DynamicTree( JTree ) :

    #---------------------------------------------------------------------------
    # Name: __init__
    # Role: class constructor
    #---------------------------------------------------------------------------
    def __init__( self ) :
        self.nodeSuffix = 0

    #---------------------------------------------------------------------------
    # Name: getSuffix
    # Role: return next suffix value to be used, after incrementing it
    #---------------------------------------------------------------------------
    def getSuffix( self ) :
        self.nodeSuffix += 1
        return self.nodeSuffix

    #---------------------------------------------------------------------------
    # Name: run
    # Role: Create, populate, & display application frame
    # Note: Called by Swing event dispatch thread
    #---------------------------------------------------------------------------
    def run( self ) :
#        frame = JFrame(
#            'DynamicTree',
#            layout = BorderLayout(),
#            locationRelativeTo = None,
#            defaultCloseOperation = JFrame.EXIT_ON_CLOSE
#        )
        self.tree  = self.makeTree()      # Keep references handy
        self.model = self.tree.getModel()
#        frame.add(
#            JScrollPane(
#                self.tree,
#                preferredSize = Dimension( 300, 150 )
#            ),
#            BorderLayout.CENTER
#        )
#        frame.add( self.buttonRow(), BorderLayout.SOUTH )
#        frame.pack()
#        frame.setVisible( 1 )

    #---------------------------------------------------------------------------
    # Name: buttonRow
    # Role: Create and return a panel holding a row of buttons
    #---------------------------------------------------------------------------
#    def buttonRow( self ) :
#        buttonPanel = JPanel( GridLayout( 0, 3 ) )
#        data = [
#            [ 'Add'   , self.addEvent ],
#            [ 'Remove', self.delEvent ],
#            [ 'Clear' , self.clsEvent ]
#        ]
#        self.buttons = {}
#        for name, handler in data :
#            self.buttons[ name ] = buttonPanel.add (
#                JButton(
#                    name,
#                    actionPerformed = handler,
#                    enabled = name != 'Remove'
#                )
#            )
#        return buttonPanel

    #---------------------------------------------------------------------------
    # Name: addEvent()
    # Role: actionperformed() method for 'Add' button
    #---------------------------------------------------------------------------
    def addEvent( self, event ) :
        sPath = self.tree.getSelectionModel().getSelectionPath()
        if sPath :                     # Use selected node
            parent = sPath.getLastPathComponent()
        else :                         # Nothing selected, use root
            parent = self.model.getRoot()
        kids = parent.getChildCount()
        child = DefaultMutableTreeNode(
            'New node %d' % self.getSuffix()
        )
        self.model.insertNodeInto( child, parent, kids )
        self.tree.scrollPathToVisible(
            TreePath( child.getPath() )
        )

    #---------------------------------------------------------------------------
    # Name: delEvent()
    # Role: actionperformed() method for 'Remove' button
    # Note: This button is only enabled when a non-root node is selected
    #---------------------------------------------------------------------------
    def delEvent( self, event ) :
        currentSelection = self.tree.getSelectionPath()
        if currentSelection :
            currentNode = currentSelection.getLastPathComponent()
            if currentNode.getParent() :
                self.model.removeNodeFromParent( currentNode )
                return

    #---------------------------------------------------------------------------
    # Name: clsEvent()
    # Role: actionperformed() method for 'Clear' button
    #---------------------------------------------------------------------------
    def clsEvent( self, event ) :
        self.model.getRoot().removeAllChildren()
        self.model.reload()

    def newTree(self, arg_root):
        self.tree = self.makeTree(arg_root)
        self.model = self.tree.getModel()

    #---------------------------------------------------------------------------
    # Name: makeTree()
    # Role: Create, populate and return an editable JTree()
    #---------------------------------------------------------------------------
    def makeTree( self, arg_root=None ) :
        #-----------------------------------------------------------------------
        # First, build the hierarchy of Tree nodes
        #-----------------------------------------------------------------------
        if arg_root == None:
            root = DefaultMutableTreeNode( 'Root Node' )
            for name in 'Parent 1,Parent 2'.split( ',' ) :
                here = DefaultMutableTreeNode( name )
                for child in 'Child 1,Child 2'.split( ',' ) :
                    here.add( DefaultMutableTreeNode( child ) )
                root.add( here )
        else:
            root = arg_root
        #-----------------------------------------------------------------------
        # Next, use the hierarchy to create a Tree Model, with a listener
        #-----------------------------------------------------------------------
        model = DefaultTreeModel(
            root,
            treeModelListener = myTreeModelListener()
        )
        #-----------------------------------------------------------------------
        # Then, build our editable JTree() using this model
        #-----------------------------------------------------------------------
        tree = JTree(
            model,
            editable = 1,
            showsRootHandles = 0,
            # showsRootHandles = 1,
            # valueChanged = self.select
        )
        #-----------------------------------------------------------------------
        # Only allow one node to be selectable at a time
        #-----------------------------------------------------------------------
        tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )
        return tree

    #---------------------------------------------------------------------------
    # Name: select()
    # Role: TreeSelectionListener valueChanged event handler
    #---------------------------------------------------------------------------
    def select( self, event ) :
        tree  = event.getSource()      # Get access to tree
        count = tree.getSelectionCount()
        sPath = tree.getSelectionModel().getSelectionPath()
        if sPath :                     # How deep is the pick?
            depth = sPath.getPathCount()
        else :                         # Nothing selected
            depth = 0
#        self.buttons[ 'Remove' ].setEnabled( count and depth > 1 )


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    # Example structure of match record
    match = {
        'tokens':{},         # {'token_name':'token_value'}
        'referer':None,
        'regex':None,
        'origin':None,
        'cookies':{},      # {cookie_key:cookie_value}
    }

    # Example structure of host record
    host = {
        'path':{},          # {url_path: [url_query]}
        'cookies':{},       # {cookie_key:cookie_value}
        'tokens':{},        # {'token_name':'token_value'}
        'origin':None,      # hostname
        'referer':None,
        'match': {},        # {'hostname':match_record}
    }

    hosts_dic = {}
    '''
    Example structure of master record for http hosts that that have relationships
    hosts_dic['example.com'] = copy.deepcopy(host)

    hosts_dic['new-example.com'] = copy.deepcopy(host)
    hosts_dic['new-example.com']['match']['example.com'] = copy.deepcopy(match)
    hosts_dic['new-example.com']['match']['example.com']['origin'] = 'example.com'
    '''

    log_columns = ['Tool','Host','Path + Query', 'Comment']

    # Use for starting point of request/response trace
    fqdn_txt_field = ''

    _debug_textarea = ''
    _extension_name = 'By association'
    _stdout = None
    _stderr = None

    # Tokens can be security related artifacts
    tokens = {}

    # Cookie values that a related to the session
    cookies = {}
    # Search terms in cookie names
    cookie_keywords = 'session|password|customer|token|service'

    # Toggle extension use
    _ss_button = None

    _tree = None
    _root = None

    #
    # implement IBurpExtender
    #

    def reset_logger(self, event):
        # clear fqdn textbox
        self.fqdn_txt_field.text = ''
        # Reset textarea displaying search tokens
        self._debug_textarea.text = ''
        self.tokens = {}
        self.hosts_dic = {}
        # Clear Table
        self._log = ArrayList()

    def toggle_ss(self, event):
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

        # Tree view
        self._tree = DynamicTree()
        self._tree.run()

        tree_pane = JScrollPane(self._tree)

        # debug output
        self._debug_textarea = JTextArea()
        self._debug_textarea.text = 'Debug output'
        self._debug_textarea.editable = True
        self._debug_textarea.wrapStyleWord = True
        self._debug_textarea.lineWrap = True
        self._debug_textarea.alignmentX = Component.LEFT_ALIGNMENT

        # Reset button
        reset_button = JButton('Reset', actionPerformed=self.reset_logger)

        # Start/Stop button
        self._ss_button = JButton('Start', actionPerformed=self.toggle_ss)

        debug_scroll_pane = JScrollPane(self._debug_textarea)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)

        # textbox
        self.fqdn_txt_field = JTextField('Type fqdn to start tracing',15)
        pnl = JPanel()
        pnl.add(self._ss_button)
        pnl.add(self.fqdn_txt_field)
        pnl.add(reset_button)


        # Top pane
        top_splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, pnl, scrollPane)

        # tabs with request/response viewers
        rr_tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        rr_tabs.addTab("Request", self._requestViewer.getComponent())
        rr_tabs.addTab("Response", self._responseViewer.getComponent())
        # Main pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_splitpane, rr_tabs)

        # customize our UI components
        self._main_tabs.addTab("Logs", self._splitpane)
        self._main_tabs.addTab("Debug", debug_scroll_pane)
        self._main_tabs.addTab("Tree view", tree_pane)

        callbacks.customizeUiComponent(self._main_tabs)
        callbacks.customizeUiComponent(self._debug_textarea)
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(rr_tabs)

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

    def getBody(self, rawMessage, parsedMessage):
        return self._helpers.bytesToString(rawMessage[parsedMessage.getBodyOffset():])

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
        if messageIsRequest:
            return
        else:
            # must be response and request
            # Start with processing http request portion of messageInfo
            parsed_http_message = self._helpers.analyzeRequest(messageInfo.getRequest())
            body = self.getBody(messageInfo.getRequest(), parsed_http_message)
            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            headers = parsed_http_message.getHeaders().toString()

            url_parsed = urlparse(url)
            hostname = url_parsed.hostname
            path = url_parsed.path
            query = url_parsed.query
            path_params = path + query

            # Do we have any persistant comments from related req/resp?
            if messageInfo.getComment():
                comment = messageInfo.getComment() + ' '

            # We are looking to add current req host as a new unseen host
            # Are any of the saved tokens in the request headers?
            if headers and not self.hosts_dic.get(hostname):
                for host, tokens in [(host, self.hosts_dic[host].get('tokens').items(),) for host in self.hosts_dic.keys()]:
                    for token_key,token_value in tokens:
                        if token_value in headers:
                            comment += 'TokenReq '
                            # Add as new host to saved list of hosts
                            self.hosts_dic[hostname] = copy.deepcopy(self.host)

                            # Save match record
                            self.hosts_dic[hostname]['match'][host] = copy.deepcopy(self.match)
                            self.hosts_dic[hostname]['match'][host]['tokens'] = {token_key:token_value}

                            if query:
                                self.hosts_dic[hostname]['path'] = {path:[query]}
                            else:
                                self.hosts_dic[hostname]['path'] = {path:[]}

                            break

                # Check if request header has any matching saved cookie values
                # from other related hosts.
                # e.g. url might contain customer_id which was obtained from anther a set-cookie
                if not self.hosts_dic.get(hostname):
                    for host, cookies in [(host, self.hosts_dic[host].get('cookies').items(),) for host in self.hosts_dic.keys()]:
                        for cookie_key,cookie_value in cookies:
                            #self._stdout.println('Checking request headers for token')
                            if cookie_value in headers:
                                comment += 'CookieReq '
                                # Add as new host to saved list of hosts
                                self.hosts_dic[hostname] = copy.deepcopy(self.host)

                                # Save match record
                                self.hosts_dic[hostname]['match'][host] = copy.deepcopy(self.match)
                                self.hosts_dic[hostname]['match'][host]['cookies'] = {cookie_key:cookie_value}

                                if query:
                                    self.hosts_dic[hostname]['path'] = {path:[query]}
                                else:
                                    self.hosts_dic[hostname]['path'] = {path:[]}

                # Look for CORS requests based on origin header
                origin_header = self.getHeaderFor(headers,'origin')

                if origin_header and not self.hosts_dic.get(hostname):
                    for host in self.hosts_dic.keys():
                        # TODO: exclude subdomain false positive
                        if host in origin_header:
                            comment  += 'Origin '
                            # Add as new host to saved list of hosts
                            self.hosts_dic[hostname] = copy.deepcopy(self.host)

                            # Save match record
                            self.hosts_dic[hostname]['match'][host] = copy.deepcopy(self.match)
                            self.hosts_dic[hostname]['match'][host]['origin'] = origin_header

                            if query:
                                self.hosts_dic[hostname]['path'] = {path:[query]}
                            else:
                                self.hosts_dic[hostname]['path'] = {path:[]}
                            break

                # Look for CORS requests based on origin header
                referer_header = self.getHeaderFor(headers,'referer')

                if referer_header and not self.hosts_dic.get(hostname):
                    for host in self.hosts_dic.keys():
                        if host in referer_header:
                            comment  += 'Referer '
                            # Add as new host to saved list of hosts
                            self.hosts_dic[hostname] = copy.deepcopy(self.host)

                            # Save match record
                            self.hosts_dic[hostname]['match'][host] = copy.deepcopy(self.match)
                            self.hosts_dic[hostname]['match'][host]['referer'] = origin_header

                            if query:
                                self.hosts_dic[hostname]['path'] = {path:[query]}
                            else:
                                self.hosts_dic[hostname]['path'] = {path:[]}
                            break

            # Anaylyze http response
            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            parsed_http_message = self._helpers.analyzeResponse(messageInfo.getResponse())
            body = self.getBody(messageInfo.getResponse(), parsed_http_message)
            mime_type = parsed_http_message.getInferredMimeType()

            headers = parsed_http_message.getHeaders()

            url_parsed = urlparse(url)
            hostname = url_parsed.hostname
            path = url_parsed.path
            query = url_parsed.query
            path_params = path
            if query: path_params += '?' + query
            bearer_token = ''
            session_token = ''

            cookies = self._helpers.analyzeResponse(messageInfo.getResponse()).getCookies()
            cookie_keywords = self.cookie_keywords
            session_cookies = [(cookie.getName(),cookie.getValue(),)
                                for cookie in cookies
                                    if re.search(cookie_keywords,cookie.getName().lower())]

            # Does request contain item of interest. Right now this is hostname based
            if (self.fqdn_txt_field.getText().lower() != '' \
                and self.fqdn_txt_field.getText().lower() in hostname) \
                or self.hosts_dic.get(hostname):

                # Has the host been tracked?
                if not self.hosts_dic.get(hostname):
                    comment += 'SearchMatch '
                    # Add as new host to saved list of hosts
                    self.hosts_dic[hostname] = copy.deepcopy(self.host)

                    # Save match record
                    self.hosts_dic[hostname]['match'][hostname] = copy.deepcopy(self.match)
                    self.hosts_dic[hostname]['match'][hostname]['regex'] = self.fqdn_txt_field.getText()

                    if query:
                        self.hosts_dic[hostname]['path'] = {path:[query]}
                    else:
                        self.hosts_dic[hostname]['path'] = {path:[]}
                else:
                    # Host has been seen already
                    # Check to see if path has been tracked
                    # Host + path tracked
                    if path in self.hosts_dic[hostname]['path'].keys():
                        # Query not seen?
                        if query and not query in self.hosts_dic[hostname]['path'][path]:
                            self.hosts_dic[hostname]['path'][path] = self.hosts_dic[hostname]['path'][path] + [query]
                    else: # Path not seen
                        if query:
                            self.hosts_dic[hostname]['path'][path] = [query]
                        else:
                            self.hosts_dic[hostname]['path'][path] = []

                # Check if known host's response has bearer token or sessionid associated with current host
                # Obtain tokens from json responses
                if mime_type.lower() == 'json':
                    bearer_tokens = self.getBearerTokens(body)

                    for token_key,token_value in bearer_tokens:
                        if token_value:
                            comment += 'BearerTokenResp '
                            self.hosts_dic[hostname]['tokens'][token_key] = token_value

                    session_tokens = self.getSessionTokens(body)

                    for token_key,token_value in session_tokens:
                        if token_value:
                            comment += 'SessionTokenResp '
                            self.hosts_dic[hostname]['tokens'][token_key] = token_value


                # Store cookie values from known hosts
                # which may show up in related requests from unknown hosts
                for cookie_name, cookie_value in session_cookies:
                    comment += 'CookieResp '
                    self.hosts_dic[hostname]['cookies'][cookie_name] = cookie_value


            # Apply our collected comments.
            messageInfo.setComment(comment)

            # create a new log entry with the message details, if host is being tracked
            if self.hosts_dic.get(hostname):
                self._lock.acquire()
                row = self._log.size()
                self._log.add(
                    LogEntry(toolFlag,
                        self._callbacks.saveBuffersToTempFiles(messageInfo),
                        path_params,
                        hostname,
                        comment,
                    )
                )
                self.fireTableRowsInserted(row, row)
                self._lock.release()

                # Update debug textarea
                self._debug_textarea.text = 'Discovered hosts\n'
                self._debug_textarea.text += json.dumps(self.hosts_dic, indent=4, sort_keys=True)

                # Add hosts to tree view
                # This is very inefficient code for jtree. Model events should
                # be used to auto update the tree. Couldn't figure out how to do it.
                root = DefaultMutableTreeNode( self.fqdn_txt_field.getText() )

                for host in self.hosts_dic:
                    host_branch = DefaultMutableTreeNode(host)
                    for url in self.hosts_dic[host]['path'].keys():
                        host_branch.add( DefaultMutableTreeNode( url ) )
                    root.add( host_branch )
                self._tree.newTree(root)


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
