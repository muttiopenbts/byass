'''
Code based on PyRules project at https://github.com/DanNegrea/PyRules
The goal is to make testing multi-staged APIs easier, and the user defined rules
more intuitive.

Purpose:
Allows Burp user to embed markers/tags into requests which can then be passed
through this tool, and have the user defined rules on replacing the markers
with strings of their choice.

Similar functionality to Postman.

Usage:
Define your rules within the python dictionary 'settings', 'tags' list.
settings = {
	'tags': [
		{'id':"{{customer_id}}", 'type':'string','content':'201803051',},
		{'id':"{{code}}", 'type':'string','content':code,},
		{
			'id':"{{service_key}}",
			'type':'code',
			'content':[generate_signature,
			{
				'signer':signer,
				'command':command,
				'multi_tenant_priv_key':multi_tenant_priv_key,
				'service_name':service_name,
				'messageInfo':messageInfo,
				'helpers':helpers,
			},]
		,},
	],
}

'id' = 		{{[a-zA-Z_]}}. This is the identifier that you will place in your http
			requests.

'type' = 	'string' or 'code'. Refer to 'content' for definition.

'content' =	Based on 'type' field.
			'string' types are a one-to-one replacement with 'content' value when
			a match is made against an 'id'/tag/marker.
			'string' can be a literal or a varible.
			'code' will call a user defined function to
			dynamically generate the replacement text.
			The format for a code call is a list of length 2, index 0 = function
			name, and index 1 = dictionary of keyword arguments to the function.

Your

Markers/tags are currently supported in Burp repeater and intruder tools.
Tags can be placed in the url, header or body portions of a request.
Example request:
POST /root/login/auth HTTP/1.1
Host: api.authapi.net
Connection: close
Content-Type: application/json
Content-Length: 78

{
    "code": "{{code}}",
    "redirectUri": "https://something.com/oauth"
}

To view the newly modified request(s), you must install Burp's 'Custom logger'
extension.
'''

import re
import os
import subprocess
from urlparse import urlparse
import json

script_path = os.getcwd()
# Create libs under pyrules folder and place binary within libs folder.
signer = script_path + '/libs/mybinary'
command = 'sign'
# Create keys under pyrules folder and place private key within keys folder.
multi_tenant_priv_key_path = script_path + '/keys/key.priv'
multi_tenant_priv_key = ''
service_name = '666999666'
target_url = ''

# TODO: Reading private keys from fs should only be done once.
with open(multi_tenant_priv_key_path, 'r') as file:
 		multi_tenant_priv_key = file.read()


'''
Global variables:
token <bearer token>
code <authorization token|code>
'''

def generate_signature(kwargs):
	import subprocess
	import re

	# Generate signature based on url
	signer = kwargs['signer']
	command = kwargs['command']
	multi_tenant_priv_key = kwargs['multi_tenant_priv_key']
	service_name = kwargs['service_name']
	regex_remove_port = r":(\d)+?/"
	messageInfo = kwargs.get('messageInfo')
	helpers = kwargs.get('helpers')

	# burp url has port number which affects signature generation
	full_url = helpers.analyzeRequest(messageInfo).getUrl().toString()
	# Remove port number
	target_url = re.sub(regex_remove_port, '/', full_url, 0)

	# Replace tags in url because service_key is derived from it.
	target_url = replace_tags(content=target_url,tags=settings.get('tags'))

	# Generate signature based on url
	signature = subprocess.check_output([
		signer,
		command,
		multi_tenant_priv_key,
		service_name,
		target_url,
	])
	return signature[:-1] # Remove trailing '\n'

#Python rules go here
global settings
settings = {
	'tags': [
		{'id':"{{customer_id}}", 'type':'string','content':'42134123',},
		{'id':"{{code}}", 'type':'string','content':code,},
		{'id':"{{bearer}}", 'type':'string','content':token,},
		{'id':"{{service_name}}", 'type':'string','content':'432432',},
		{'id':"{{provider}}", 'type':'string','content':'4324321',},
		{'id':"{{instance_id}}", 'type':'string','content':'1',},
		{
			'id':"{{service_key}}",
			'type':'code',
			'content':[generate_signature,
			{
				'signer':signer,
				'command':command,
				'multi_tenant_priv_key':multi_tenant_priv_key,
				'service_name':service_name,
				'messageInfo':messageInfo,
				'helpers':helpers,
			},]
		,},
	],
}


def get_json_value(**kwargs):
	import json

	key = kwargs['key']
	body = kwargs['body']
	log = kwargs['log']

	try:
		json_dict = json.loads(body) # becomes dict

		# Token identify is specific to my use case. Will use regex if need changes.
		token_name = key

		# Convert json keys to lower case before compare token_name
		found_token_list = [json_dict.get(x) for x in json_dict.keys() if token_name.lower() == x.lower()]

		if found_token_list:
			return str(found_token_list.pop())
	except Exception as e:
		log('Error: {}\nBody = {}\ngetJsonValue'.format(e,str(body)))

def get_body(rawMessage, parsedMessage, helpers):
	return helpers.bytesToString(rawMessage[parsedMessage.getBodyOffset():])


def replace_request_tag(**kwargs):
	import re
	request = kwargs['request']
	tag = kwargs['tag']
	replacement = kwargs['replacement']

	if tag and request and replacement:
		search  = re.compile(tag)

		request = re.sub( search, replacement, request )

	return request


def _get_priv_key(**kwargs):
	path_and_file = kwargs['path_and_file']

	with open(path_and_file, 'r') as file:
     		multi_tenant_priv_key = file.read()

global replace_tags
def replace_tags(**kwargs):
	import re

	content = kwargs.get('content')
	tags = kwargs.get('tags')

	regex = re.compile(ur"{{([a-zA-Z_]+)}}")
	#print headers_string
	matches = re.finditer(regex, content)

	# Extract full tag ({{service_key}}) and tag string (service_key)
	for tag_match in matches:
		global full_tag
		global tag_string
		full_tag = tag_match.group()
		tag_string = tag_match.group(1)

		# Extract user defined tag.
		user_tag = next(tag for tag in tags if tag.get('id') == full_tag)

		del full_tag
		del tag_string

		# Substitute http tag marker
		sub_regex = ur"{}".format(user_tag.get('id'))

		# In order to replace text, need to determine user tag type.
		if user_tag.get('type') == 'string' and user_tag.get('content'):
			# You can manually specify the number of replacements by changing the 4th argument
			content = re.sub(sub_regex, user_tag['content'], content, 0)
		elif user_tag.get('type') == 'code' and user_tag.get('content'):
			func = user_tag.get('content')[0]
			kwargs = user_tag.get('content')[1]
			output = func(kwargs)
			content = re.sub(sub_regex, output, content, 0)

	return content


if (toolFlag in [callbacks.TOOL_REPEATER,callbacks.TOOL_INTRUDER]) and messageIsRequest:
	# Get burp http request
	parsed_http_message = helpers.analyzeRequest(messageInfo.getRequest())
	headers = list(parsed_http_message.getHeaders())
	body = get_body(messageInfo.getRequest(), parsed_http_message, helpers)

	# Replace tags in headers
	# TODO: Run search and substition over all headers in one loop.
	# Search for token
	seperator = chr(1)
	headers_string = seperator.join(headers)
	headers_string = replace_tags(content=headers_string,tags=settings.get('tags'))

	body = replace_tags(content=body,tags=settings.get('tags'))

	# Update content length
	newRequest = helpers.buildHttpMessage(headers_string.split(seperator), body)
	messageInfo.setRequest(newRequest)

	log('Request sent:' +str(helpers.bytesToString(newRequest)))

	#log(script_path)
	#log(signature)

elif (toolFlag in [callbacks.TOOL_REPEATER,callbacks.TOOL_INTRUDER]) and not messageIsRequest:

	# Look for responses that have tokens|codes that will be used for new requests
	parsed_http_message = helpers.analyzeResponse(messageInfo.getResponse())
	body = get_body(messageInfo.getResponse(), parsed_http_message, helpers)

	#Capture the new token: if the response contains a new value, capture it and stored it in a persistent variable
	log("\n Response - processing")

	response = helpers.bytesToString( messageInfo.getResponse() )

	# Search for token
	search = re.compile("token")
	match = search.findall(response)

	if match:
		token = get_json_value(key='token', body=body, log=log)
		log("New token:")
		log(token)
	else:
		log("No token found!")

	# Search for code
	search = re.compile("code")
	match = search.findall(response)

	if match:
		code = get_json_value(key='code', body=body, log=log)
		log("New code:")
		log(code)
	else:
		log("No code found!")
