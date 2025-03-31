import json
import logging
import requests
import ast
import socket
from typing import Dict, Any, Optional, Union


class SplunkHecHandler(logging.Handler):
    """
    This module returns a python logging handler capable of sending logs records to a Splunk HTTP Event Collector
    listener.  Log records can be simple string or dictionary.  In the latter case, if the sourcetype is configured
    to be _json (or variant), JSON format of the log message will be preserved.

    Example
    -------

    .. code-block:: text

        import logging
        from splunk_hec_handler import SplunkHecHandler
        logger = logging.getLogger('SplunkHecHandlerExample')
        logger.setLevel(logging.DEBUG)

        splunk_handler = SplunkHecHandler('splunkfw.domain.tld',
                            'EA33046C-6FEC-4DC0-AC66-4326E58B54C3',
                            port=8888, proto='https', ssl_verify=True,
                            source="HEC_example")
        logger.addHandler(splunk_handler)

        logger.info("Testing Splunk HEC Info message")

    Splunk Event Output
    -------------------
    Following should result in a Splunk entry with _time set to current timestamp :

    .. code-block:: text

        {
            log_level: INFO
            message: Testing Splunk HEC Info message
        }
    References
    ----------
    #. See http://dev.splunk.com/view/event-collector/SP-CAAAE6P for 'fields'
    #. Splunk remote logging configuration
        * http://docs.splunk.com/Documentation/SplunkCloud/latest/Data/UsetheHTTPEventCollector
        * http://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
    #. To use fields, sourcetype must be specified and must allow for indexed field extractions

        .. code-block:: text

            dict_obj = {'time': 1533530023, 'fields': {'color': 'yellow', 'api_endpoint': '/results'},
                        'user': 'foobar', 'app': 'my demo', 'severity': 'low', 'error codes': [1, 23, 34, 456]}
            logger.error(dict_obj)
    """
    URL_PATTERN = "{0}://{1}:{2}/services/collector/{3}"
    TIMEOUT = 30

    def __init__(self, host: str, token: str, port: int = 8080, proto: str = 'https',
                 ssl_verify: Union[bool, str] = True, source: Optional[str] = None, index: Optional[str] = None,
                 sourcetype: Optional[str] = None, hostname: Optional[str] = None, endpoint: str = 'event',
                 empty_body: bool = False, test_connection: bool = True, app_data: Dict[str, Any] = None,
                 timeout: int = None, **kwargs):
        """
        Creates a python logging handler, capable of sending logs to Splunk server.

        :param host: Splunk server hostname or IP.
        :param token: Splunk HEC Token (see http://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector#About_Event_Collector_tokens)
        :param port: Port number of Splunk HEC listener. Default is 8080.
        :param proto: Protocol to use [http | https]. Default is 'https'.
        :param ssl_verify: SSL verification [True|False|<Path to cert>]. Default is True.
        :param source: Override source value specified in Splunk HEC configuration. Default is None.
        :param index: Override index value specified in Splunk HEC configuration. Default is None.
        :param sourcetype: Override sourcetype value specified in Splunk HEC configuration. Default is None.
        :param hostname: Specify custom host value. Defaults to socket.gethostname().
        :param endpoint: HEC endpoint type [raw|event]. Default is 'event'.
        :param empty_body: Initialize with an empty body. Default is False.
        :param test_connection: Test connection during initialization. Default is True.
        :param app_data: Application-specific data to include in every log event. Default is {}.
        :param timeout: Connection timeout in seconds. Default is 30.
        :param kwargs: Additional keyword arguments.
        """
        logging.Handler.__init__(self)
        self.host = host
        self.token = token
        self.port = int(port)
        self.proto = proto

        # Handle ssl_verify parameter
        value = ssl_verify.lower() if isinstance(ssl_verify, str) else ssl_verify
        self.ssl_verify = not (value in ["0", 0, "false", "False", False])
        self.source = source
        self.index = index
        self.sourcetype = sourcetype
        self.hostname = hostname if hostname is not None else socket.gethostname()
        self.endpoint = endpoint
        self.empty_body = empty_body
        self.test_connection = test_connection
        self.app_data = app_data if app_data is not None else {}
        self.timeout = timeout if timeout is not None else self.TIMEOUT

        # Establish requests session
        self.r = requests.session()
        self.r.max_redirects = 1
        self.r.verify = self.ssl_verify
        self.r.headers['Authorization'] = f"Splunk {self.token}"
        self.url = self.URL_PATTERN.format(self.proto, self.host, self.port, self.endpoint)

        # Test connection if enabled
        if self.test_connection:
            try:
                with socket.socket() as s:
                    s.settimeout(self.timeout)
                    s.connect((self.host, self.port))
            except Exception as err:
                logging.debug(f"Failed to connect to remote Splunk server ({self.host}:{self.port}). Exception: {err}")
                raise err

    def emit(self, record):
        """
        Send log record to Splunk HEC listener
        :param record: string or dictionary. String record is logged as 'message' in Splunk.
        Dictionary is preserved as JSON object.  log_level is set to requested log level.
        :return: None
        """
        if self.empty_body:
            body = {}
        else:
            body = {'log_level': record.levelname}

            # Include application-specific data
            if self.app_data:
                body.update(self.app_data)

            # Add useful record attributes by default
            for field in ('logger', 'lineno', 'funcName', 'module', 'process'):
                value = getattr(record, field, None)
                if value is not None:
                    body[field] = value

        try:
            if isinstance(record.msg, dict):
                body.update(record.msg)
            else:
                try:
                    # Try to convert string representation to object
                    parsed_msg = ast.literal_eval(str(record.msg))
                    if isinstance(parsed_msg, dict):
                        body.update(parsed_msg)
                    else:
                        body.update({'message': record.msg})
                except (ValueError, SyntaxError):
                    body.update({'message': record.msg})
        except Exception as e:
            logging.debug(f"Unable to serialize message ({record.msg}) to Splunk log format: {str(e)}")
            body.update({'message': str(record.msg)})

        event = dict({'host': self.hostname, 'event': body})

        # Splunk 7.x does not like empty fields
        if self.source is not None:
            event['source'] = self.source

        if self.sourcetype is not None:
            event['sourcetype'] = self.sourcetype

        if self.index is not None:
            event['index'] = self.index

        # Use timestamp from event if available
        # Note, 'time' in 'fields' will override this
        if 'time' in body.keys():
            event['time'] = body['time']
        # Default to log record create time and preserve fractional seconds
        else:
            event['time'] = record.created

        # fields
        # This specifies explicit custom fields that are separate from the main "event" data.
        # This method is useful if you don't want to include the custom fields with the event data,
        # but you want to be able to annotate the data with some extra information, such as where it came from.
        # http://dev.splunk.com/view/event-collector/SP-CAAAFB6
        if ('fields' in body.keys() and hasattr(body['fields'], 'items')) or ('time' in body.keys()):
            try:
                for k, v in body['fields'].items():
                    if k in ['host', 'source', 'sourcetype', 'time', 'index']:
                        event[k] = v
                    else:
                        try:
                            if type(v) in [str, list]:
                                event.setdefault('fields', {})[k] = v
                            else:
                                # Splunk fails to index event if fields contains values of type other than str or list
                                # i.e HTTP Status: 400, Reason: Bad Request,
                                # Content: {"text":" Error in handling indexed fields", "code":15}
                                event.setdefault('fields', {})[k] = str(v)
                        except Exception:
                            pass
            except Exception as e:
                logging.debug(f"Error processing fields: {str(e)}")
            else:
                body.pop('fields')

        try:
            # 'skipkeys' - If skipkeys is true (default: False), then dict keys that are not of a basic type
            # (str, int, float, bool, None) will be skipped instead of raising a TypeError.
            # 'default' - If specified, default should be a function that gets called for objects that can’t otherwise
            # be serialized. It should return a JSON encode-able version of the object or raise a TypeError.
            data = json.dumps(event, sort_keys=True, skipkeys=True, default=self.serializer)
        except Exception as e:
            logging.debug(f"Unable to serialize event data to Splunk log format: {str(e)}")
            # Fallback to simplified event
            try:
                simplified_event = {
                    'host': self.hostname,
                    'event': {'log_level': record.levelname, 'message': str(record.msg)},
                    'time': record.created
                }
                data = json.dumps(simplified_event)
            except Exception:
                # If all serialization fails, we can't send the log
                return

        try:
            req = self.r.post(self.url, data=data, timeout=self.timeout)
            req.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.debug(f"Failed to emit record to Splunk server ({self.host}:{self.port}).  Exception raised: {err}")
            raise

    @staticmethod
    def serializer(obj):
        if type(obj) in [set, frozenset, range]:
            return list(obj)
        else:
            try:
                return str(obj)
            except Exception:
                raise

    def close(self):
        try:
            self.r.close()
        except Exception:
            pass
        finally:
            super().close()
