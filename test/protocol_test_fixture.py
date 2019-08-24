"""
A test fixture for PyLink protocol modules.
"""
import time
import unittest
import collections
from unittest.mock import patch

from pylinkirc import conf, world
from pylinkirc.classes import User, Server, Channel

class DummySocket():
    def __init__(self):
        #self.recv_messages = collections.deque()
        self.sent_messages = collections.deque()

    @staticmethod
    def connect(address):
        return
    '''
    def recv(bufsize, *args):
        if self.recv_messages:
            data = self.recv_messages.popleft()
            print('<-', data)
            return data
        else:
            return None
    '''

    def recv(bufsize, *args):
        raise NotImplementedError

    def send(self, data):
        print('->', data)
        self.sent_messages.append(data)

class BaseProtocolTest(unittest.TestCase):
    proto_class = None
    netname = 'test'
    serverdata = conf.conf['servers'][netname]

    def setUp(self):
        if not self.proto_class:
            raise RuntimeError("Must set target protocol module in proto_class")
        self.p = self.proto_class(self.netname)

        # Stub connect() and the socket for now...
        self.p.connect = lambda self: None
        self.p.socket = DummySocket()

        if self.serverdata:
            self.p.serverdata = self.serverdata

    def _make_user(self, nick, uid, ts=None, sid=None, **kwargs):
        """
        Creates a user for testing.
        """
        if ts is None:
            ts = int(time.time())
        userobj = User(self.p, nick, ts, uid, sid, **kwargs)
        self.p.users[uid] = userobj
        return userobj

    ### STATEKEEPING FUNCTIONS

    def test_nick_to_uid(self):
        self.assertEqual(self.p.nick_to_uid('TestUser'), None)

        self._make_user('TestUser', 'testuid1')

        self.assertEqual(self.p.nick_to_uid('TestUser'), 'testuid1')
        self.assertEqual(self.p.nick_to_uid('TestUser', multi=True), ['testuid1'])
        self.assertEqual(self.p.nick_to_uid('BestUser'), None)
        self.assertEqual(self.p.nick_to_uid('RestUser', multi=True), [])

        self._make_user('TestUser', 'testuid2')
        self.assertEqual(self.p.nick_to_uid('TestUser', multi=True), ['testuid1', 'testuid2'])

    def test_is_internal(self):
        self.p.servers['internalserver'] = Server(self.p, None, 'internal.server', internal=True)
        self.p.sid = 'internalserver'
        self.p.servers['externalserver'] = Server(self.p, None, 'external.server', internal=False)

        iuser = self._make_user('someone', 'uid1', sid='internalserver')
        euser = self._make_user('sometwo', 'uid2', sid='externalserver')

        self.assertTrue(self.p.is_internal_server('internalserver'))
        self.assertFalse(self.p.is_internal_server('externalserver'))
        self.assertTrue(self.p.is_internal_client('uid1'))
        self.assertFalse(self.p.is_internal_client('uid2'))

    def test_is_manipulatable(self):
        self.p.servers['serv1'] = Server(self.p, None, 'myserv.local', internal=True)
        iuser = self._make_user('yes', 'uid1', sid='serv1', manipulatable=True)
        euser = self._make_user('no', 'uid2', manipulatable=False)

        self.assertTrue(self.p.is_manipulatable_client('uid1'))
        self.assertFalse(self.p.is_manipulatable_client('uid2'))

    def test_get_service_bot(self):
        self.assertFalse(self.p.get_service_bot('nonexistent'))

        regular_user = self._make_user('Guest12345', 'Guest12345@1')
        service_user = self._make_user('MyServ', 'MyServ@2')
        service_user.service = 'myserv'

        self.assertFalse(self.p.get_service_bot('Guest12345@1'))

        with patch.dict(world.services, {'myserv': 'myserv instance'}, clear=True):
            self.assertEqual(self.p.get_service_bot('MyServ@2'), 'myserv instance')

    def test_to_lower(self):
        check = lambda inp, expected: self.assertEqual(self.p.to_lower(inp), expected)
        check_unchanged = lambda inp: self.assertEqual(self.p.to_lower(inp), inp)

        check('BLAH!', 'blah!')
        check('BLAH!', 'blah!')  # since we memoize
        check_unchanged('zabcdefghijklmnopqrstuvwxy')
        check('123Xyz !@#$%^&*()-=+', '123xyz !@#$%^&*()-=+')

        if self.p.casemapping == 'rfc1459':
            check('hello [] {} |\\ ~^', 'hello [] [] \\\\ ^^')
            check('{Test Case}', '[test case]')
        else:
            check_unchanged('hello [] {} |\\ ~^')
            check('{Test Case}', '{test case}')

    def test_is_nick(self):
        assertT = lambda inp: self.assertTrue(self.p.is_nick(inp))
        assertF = lambda inp: self.assertFalse(self.p.is_nick(inp))

        assertT('test')
        assertT('PyLink')
        assertT('[bracketman]')
        assertT('{RACKETman}')
        assertT('bar|tender')
        assertT('\\bar|bender\\')
        assertT('GL|ovd')
        assertT('B')
        assertT('`')
        assertT('Hello123')
        assertT('test-')
        assertT('test-test')
        assertT('_jkl9')
        assertT('_-jkl9')

        assertF('')
        assertF('?')
        assertF('nick@network')
        assertF('Space flight')
        assertF(' ')
        assertF(' Space blight')
        assertF('0')
        assertF('-test')
        assertF('#lounge')
        assertF('\\bar/bender\\')
        assertF('GL/ovd') # Technically not valid, but some IRCds don't care ;)
        assertF('100AAAAAC') # TS6 UID

        self.assertFalse(self.p.is_nick('longnicklongnicklongnicklongnicklongnicklongnick', nicklen=20))
        self.assertTrue(self.p.is_nick('ninechars', nicklen=9))
        self.assertTrue(self.p.is_nick('ChanServ', nicklen=20))
        self.assertTrue(self.p.is_nick('leneight', nicklen=9))
        self.assertFalse(self.p.is_nick('bitmonster', nicklen=9))
        self.assertFalse(self.p.is_nick('ninecharsplus', nicklen=12))

    def test_is_channel(self):
        assertT = lambda inp: self.assertTrue(self.p.is_channel(inp))
        assertF = lambda inp: self.assertFalse(self.p.is_channel(inp))

        assertT('#test')
        assertT('#')
        assertT('#a#b#c')

        assertF('nick!user@host')
        assertF('&channel')  # we don't support these yet
        assertF('lorem ipsum')

    def test_is_ascii(self):
        assertT = lambda inp: self.assertTrue(self.p._isASCII(inp))
        assertF = lambda inp: self.assertFalse(self.p._isASCII(inp))

        assertT('iotgjw@sy9!4py645ujg990rEYghiwaK0r4{SEFIre')
        assertT('touche')
        assertF('touché')
        assertF('测试1')

    def test_is_server_name(self):
        self.assertTrue(self.p.is_server_name('test.local'))
        self.assertTrue(self.p.is_server_name('IRC.example.com'))
        self.assertTrue(self.p.is_server_name('services.'))
        self.assertFalse(self.p.is_server_name('.org'))
        self.assertFalse(self.p.is_server_name('bacon'))

    def test_is_hostmask(self):
        assertT = lambda inp: self.assertTrue(self.p.is_hostmask(inp))
        assertF = lambda inp: self.assertFalse(self.p.is_hostmask(inp))

        assertT('nick!user@host')
        assertT('abc123!~ident@ip1-2-3-4.example.net')

        assertF('brick!user')
        assertF('user@host')
        assertF('!@')
        assertF('!')
        assertF('@abcd')
        assertF('#channel')
        assertF('test.host')
        assertF('nick ! user @ host')
        assertF('alpha!beta@example.net#otherchan') # Janus workaround

    def test_get_SID(self):
        self.p.servers['serv1'] = Server(self.p, None, 'myserv.local', internal=True)

        check = lambda inp, expected: self.assertEqual(self.p._get_SID(inp), expected)
        check('myserv.local', 'serv1')
        check('MYSERV.local', 'serv1')
        check('serv1', 'serv1')
        check('other.server', 'other.server')

    def test_get_UID(self):
        u = self._make_user('you', uid='100')
        check = lambda inp, expected: self.assertEqual(self.p._get_UID(inp), expected)

        check('you', '100')    # nick to UID
        check('YOu', '100')
        check('100', '100')    # already a UID
        check('Test', 'Test')  # non-existent

    def test_get_UID(self):
        u = self._make_user('you', uid='100')
        check = lambda inp, expected: self.assertEqual(self.p._get_UID(inp), expected)

        check('you', '100')    # nick to UID
        check('YOu', '100')
        check('100', '100')    # already a UID
        check('Test', 'Test')  # non-existent

    # TODO: _squit wrapper

    def test_parse_modes_channel_rfc(self):
        # These are basic tests that only use RFC 1459 defined modes.
        # IRCds supporting more complex modes can define new test cases if needed.
        u = self._make_user('testuser', uid='100')

        c = self.p.channels['#testruns'] = Channel(self.p, name='#testruns')

        self.assertEqual(
            self.p.parse_modes('#testruns', ['+m']),
            [('+m', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+l', '3']),
            [('+l', '3')]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+ntl', '59']),
            [('+n', None), ('+t', None), ('+l', '59')]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+k-n', 'test']),
            [('+k', 'test'), ('-n', None)]
        )

        self.assertEqual(
            self.p.parse_modes('#testruns', ['+o', '102']),  # unknown UID
            []
        )

        c.users.add(u)
        u.channels.add(c)

        self.assertEqual(
            self.p.parse_modes('#testruns', ['+o', '100']),
            [('+o', '100')]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+vip', '100']),
            [('+v', '100'), ('+i', None), ('+p', None)]
        )

    def test_parse_modes_channel_rfc(self):
        # These are basic tests that only use RFC 1459 defined modes.
        # IRCds supporting more complex modes can define new test cases if needed.
        c = self.p.channels['#testruns'] = Channel(self.p, name='#testruns')

        self.assertEqual(
            self.p.parse_modes('#testruns', ['+m']),   # add modes
            [('+m', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['-tn']),  # remove modes
            [('-t', None), ('-n', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#TESTRUNS', ['-tn']),  # different case target
            [('-t', None), ('-n', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+l', '3']),  # modes w/ arguments
            [('+l', '3')]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+nlt', '59']),  # combination
            [('+n', None), ('+l', '59'), ('+t', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+k-n', 'test']),  # swapping +/-
            [('+k', 'test'), ('-n', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['n-s']),  # sloppy syntax
            [('+n', None), ('-s', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+bmi', '*!test@example.com']),
            [('+b', '*!test@example.com'), ('+m', None), ('+i', None)]
        )

    def test_parse_modes_prefixmodes_rfc(self):
        c = self.p.channels['#testruns'] = Channel(self.p, name='#testruns')
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+ov', '102', '101']),  # unknown UIDs are ignored
            []
        )
        u = self._make_user('test100', uid='100')
        c.users.add(u)
        u.channels.add(c)

        self.assertEqual(
            self.p.parse_modes('#testruns', ['+o', '100']),
            [('+o', '100')]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['+vip', '100']),
            [('+v', '100'), ('+i', None), ('+p', None)]
        )
        self.assertEqual(
            self.p.parse_modes('#testruns', ['-o+bn', '100', '*!test@example.com']),
            [('-o', '100'), ('+b', '*!test@example.com'), ('+n', None)]
        )
        self.assertEqual(
            # 2nd user missing
            self.p.parse_modes('#testruns', ['+oovv', '100', '102', '100', '102']),
            [('+o', '100'), ('+v', '100')]
        )

        u2 = self._make_user('test102', uid='102')
        c.users.add(u2)
        u2.channels.add(c)

        self.assertEqual(
            # two users interleaved
            self.p.parse_modes('#testruns', ['+oovv', '100', '102', '100', '102']),
            [('+o', '100'), ('+o', '102'), ('+v', '100'), ('+v', '102')]
        )

        self.assertEqual(
            # Mode cycle
            self.p.parse_modes('#testruns', ['+o-o', '100', '100']),
            [('+o', '100'), ('-o', '100')]
        )

    def test_parse_modes_channel_ban_complex(self):
        c = self.p.channels['#testruns'] = Channel(self.p, name='#testruns')
        self.assertEqual(
            # add first ban, but don't remove second because it doesn't exist
            self.p.parse_modes('#testruns', ['+b-b', '*!*@test1', '*!*@test2']),
            [('+b', '*!*@test1')],
            "First ban should have been added, and second ignored"
        )
        self.p.apply_modes('#testruns', [('+b', '*!*@test1')])
        self.assertEqual(
            # remove first ban because it matches case
            self.p.parse_modes('#testruns', ['-b', '*!*@test1']),
            [('-b', '*!*@test1')],
            "First ban should have been removed (same case)"
        )
        self.assertEqual(
            # remove first ban despite different case
            self.p.parse_modes('#testruns', ['-b', '*!*@TEST1']),
            [('-b', '*!*@test1')],
            "First ban should have been removed (different case)"
        )
        self.p.apply_modes('#testruns', [('+b', '*!*@Test2')])
        self.assertEqual(
            # remove second ban despite different case
            self.p.parse_modes('#testruns', ['-b', '*!*@test2']),
            [('-b', '*!*@Test2')],
            "Second ban should have been removed (different case)"
        )

    def test_parse_modes_user_rfc(self):
        u = self._make_user('testuser', uid='100')

        self.assertEqual(
            self.p.parse_modes('100', ['+i-w+x']),
            [('+i', None), ('-w', None), ('+x', None)]
        )
        self.assertEqual(
            # Sloppy syntax, but OK
            self.p.parse_modes('100', ['wx']),
            [('+w', None), ('+x', None)]
        )

    def test_apply_modes_channel_simple(self):
        c = self.p.channels['#'] = Channel(self.p, name='#')

        self.p.apply_modes('#', [('+m', None)])
        self.assertEqual(c.modes, {('m', None)})

        self.p.apply_modes('#', [('-m', None)])
        self.assertFalse(c.modes)  # assert is empty

    def test_apply_modes_channel_add_remove(self):
        c = self.p.channels['#'] = Channel(self.p, name='#')

        self.p.apply_modes('#', [('+i', None)])
        self.assertEqual(c.modes, {('i', None)})

        self.p.apply_modes('#', [('+n', None), ('-i', None)])
        self.assertEqual(c.modes, {('n', None)})

    def test_apply_modes_channel_remove_nonexistent(self):
        c = self.p.channels['#abc'] = Channel(self.p, name='#abc')
        self.p.apply_modes('#abc', [('+t', None)])
        self.assertEqual(c.modes, {('t', None)})

        self.p.apply_modes('#abc', [('-n', None), ('-i', None)])
        self.assertEqual(c.modes, {('t', None)})

    def test_apply_modes_channel_typeC(self):
        c = self.p.channels['#abc'] = Channel(self.p, name='#abc')
        self.p.apply_modes('#abc', [('+t', None), ('+l', '30')])
        self.assertEqual(c.modes, {('t', None), ('l', '30')})

        self.p.apply_modes('#abc', [('+l', '55')])
        self.assertEqual(c.modes, {('t', None), ('l', '55')})

        self.p.apply_modes('#abc', [('-l', None)])
        self.assertEqual(c.modes, {('t', None)})

    def test_apply_modes_channel_typeB(self):
        c = self.p.channels['#pylink'] = Channel(self.p, name='#pylink')
        self.p.apply_modes('#pylink', [('+k', 'password123'), ('+s', None)])
        self.assertEqual(c.modes, {('s', None), ('k', 'password123')})

        self.p.apply_modes('#pylink', [('+k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'abcdef')])
        # Trying to remove with wrong key is a no-op
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None)})

        self.p.apply_modes('#pylink', [('+k', '12345')])
        self.assertEqual(c.modes, {('s', None), ('k', '12345')})

    def test_apply_modes_channel_typeA(self):
        c = self.p.channels['#pylink'] = Channel(self.p, name='#pylink')
        self.p.apply_modes('#pylink', [('+k', 'password123'), ('+s', None)])
        self.assertEqual(c.modes, {('s', None), ('k', 'password123')})

        self.p.apply_modes('#pylink', [('+k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'abcdef')])
        # Trying to remove with wrong key is a no-op
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None)})

        self.p.apply_modes('#pylink', [('+k', '12345')])
        self.assertEqual(c.modes, {('s', None), ('k', '12345')})

    def test_apply_modes_channel_typeA(self):
        c = self.p.channels['#pylink'] = Channel(self.p, name='#pylink')
        self.p.apply_modes('#pylink', [('+k', 'password123'), ('+s', None)])
        self.assertEqual(c.modes, {('s', None), ('k', 'password123')})

        self.p.apply_modes('#pylink', [('+k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'abcdef')])
        # Trying to remove with wrong key is a no-op
        self.assertEqual(c.modes, {('s', None), ('k', 'qwerty')})

        self.p.apply_modes('#pylink', [('-k', 'qwerty')])
        self.assertEqual(c.modes, {('s', None)})

        self.p.apply_modes('#pylink', [('+k', '12345')])
        self.assertEqual(c.modes, {('s', None), ('k', '12345')})

    def test_apply_modes_channel_typeA(self):
        c = self.p.channels['#Magic'] = Channel(self.p, name='#Magic')
        self.p.apply_modes('#Magic', [('+b', '*!*@test.host'), ('+b', '*!*@best.host')])
        self.assertEqual(c.modes, {('b', '*!*@test.host'), ('b', '*!*@best.host')}, "Bans should be added")

        # This should be a no-op
        self.p.apply_modes('#Magic', [('-b', '*!*non-existent')])
        self.assertEqual(c.modes, {('b', '*!*@test.host'), ('b', '*!*@best.host')}, "Trying to unset non-existent ban should be no-op")

        # Simple removal
        self.p.apply_modes('#Magic', [('-b', '*!*@test.host')])
        self.assertEqual(c.modes, {('b', '*!*@best.host')}, "Ban on *!*@test.host be removed (same case as original)")

        # Removal but different case than original
        self.p.apply_modes('#Magic', [('-b', '*!*@BEST.HOST')])
        self.assertFalse(c.modes, "Ban on *!*@best.host should be removed (different case)")

    def test_apply_modes_channel_mode_cycle(self):
        c = self.p.channels['#Magic'] = Channel(self.p, name='#Magic')
        self.p.apply_modes('#Magic', [('+b', '*!*@example.net'), ('-b', '*!*@example.net')])
        self.assertEqual(c.modes, set(), "Ban should have been removed (same case)")

        self.p.apply_modes('#Magic', [('+b', '*!*@example.net'), ('-b', '*!*@Example.net')])
        self.assertEqual(c.modes, set(), "Ban should have been removed (different case)")

        u = self._make_user('nick', uid='user')
        c.users.add(u.uid)
        u.channels.add(c)

        self.p.apply_modes('#Magic', [('+o', 'user'), ('-o', 'user')])
        self.assertEqual(c.modes, set(), "No prefixmodes should have been set")
        self.assertFalse(c.is_op('user'))
        self.assertFalse(c.get_prefix_modes('user'))

    # TODO: test cycling +o/-o in one mode
    def test_apply_modes_channel_prefixmodes(self):
        # Make some users
        c = self.p.channels['#staff'] = Channel(self.p, name='#staff')
        u1 = self._make_user('user100', uid='100')
        u2 = self._make_user('user101', uid='101')
        c.users.add(u1.uid)
        u1.channels.add(c)
        c.users.add(u2.uid)
        u2.channels.add(c)

        # Set modes
        self.p.apply_modes('#staff', [('+o', '100'), ('+v', '101'), ('+t', None)])
        self.assertEqual(c.modes, {('t', None)})

        # State checks, lots of them... TODO: move this into Channel class tests
        self.assertTrue(c.is_op('100'))
        self.assertTrue(c.is_op_plus('100'))
        self.assertFalse(c.is_halfop('100'))
        self.assertTrue(c.is_halfop_plus('100'))
        self.assertFalse(c.is_voice('100'))
        self.assertTrue(c.is_voice_plus('100'))
        self.assertEqual(c.get_prefix_modes('100'), ['op'])

        self.assertTrue(c.is_voice('101'))
        self.assertTrue(c.is_voice_plus('101'))
        self.assertFalse(c.is_halfop('101'))
        self.assertFalse(c.is_halfop_plus('101'))
        self.assertFalse(c.is_op('101'))
        self.assertFalse(c.is_op_plus('101'))
        self.assertEqual(c.get_prefix_modes('101'), ['voice'])

        self.assertFalse(c.prefixmodes['owner'])
        self.assertFalse(c.prefixmodes['admin'])
        self.assertEqual(c.prefixmodes['op'], {'100'})
        self.assertFalse(c.prefixmodes['halfop'])
        self.assertEqual(c.prefixmodes['voice'], {'101'})

        self.p.apply_modes('#staff', [('-o', '100')])
        self.assertEqual(c.modes, {('t', None)})
        self.assertFalse(c.get_prefix_modes('100'))
        self.assertEqual(c.get_prefix_modes('101'), ['voice'])

    def test_apply_modes_user(self):
        u = self._make_user('nick', uid='user')
        self.p.apply_modes('user', [('+o', None), ('+w', None)])
        self.assertEqual(u.modes, {('o', None), ('w', None)})
        self.p.apply_modes('user', [('-o', None), ('+i', None)])
        self.assertEqual(u.modes, {('i', None), ('w', None)})

    # TODO: test type coersion if channel or mode targets are ints
    # TODO: check the output of parse_modes() here too
    def test_parse_apply_channel_key(self):
        # Test /mode #channel -k * => /mode #channel -k PASSWORD  coersion in parse_modes()
        # Note: strangely enough, the coersion is actually in parse_modes() as a special case
        c = self.p.channels['#pylink'] = Channel(self.p, name='#pylink')

        modes = self.p.parse_modes('#pylink', ['+ntk', 'foobar'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('t', None), ('k', 'foobar')}, "Key should have been added")

        modes = self.p.parse_modes('#pylink', ['+k', 'aBcDeF'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('t', None), ('k', 'aBcDeF')}, "Key should have been changed")

        # Mismatched: should be no-op
        modes = self.p.parse_modes('#pylink', ['-k', '1111111'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('t', None), ('k', 'aBcDeF')}, "Key should not have been changed")

        # Matching key: should remove key
        modes = self.p.parse_modes('#pylink', ['-k', 'aBcDeF'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('t', None)}, "Key should have been removed (same as original)")

        modes = self.p.parse_modes('#pylink', ['+k', 'AbCdEfG'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('t', None), ('k', 'AbCdEfG')}, "Key should have been readded")

        # * as key: should remove key (Charybdis TS6, ngIRCd)
        modes = self.p.parse_modes('#pylink', ['-kt', '*'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None)}, "Key should have been removed (-k *)")

        modes = self.p.parse_modes('#pylink', ['+k', 'AbCdEfG'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None), ('k', 'AbCdEfG')}, "Key should have been readded")

        # Mismatched case - treat this as remove
        # Some IRCds allow this (Unreal, P10), others do not (InspIRCd). If
        # the IRCd let this message through we should probably remove it anyways.
        # Note: Charybdis and ngIRCd do -k * removal instead so this case will never happen there
        modes = self.p.parse_modes('#pylink', ['-k', 'abcdefg'])
        self.p.apply_modes('#pylink', modes)
        self.assertEqual(c.modes, {('n', None)}, "Key should have been removed (-k with different case)")