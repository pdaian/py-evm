import os, sys, json

import pytest
import subprocess
import logging
from subprocess import check_output
from evm import deployment

from evm.utils.address import (
    generate_contract_address,
)

from evm.constants import (
    CREATE_CONTRACT_ADDRESS,
)

from evm.db import (
    get_db_backend,
)
from evm.db.chain import BaseChainDB

#from evm import deployment

from eth_utils import (
    keccak,
)

from evm.exceptions import (
    VMError,
)
from evm.rlp.headers import (
    BlockHeader,
)
from evm.vm.forks import (
    HomesteadVM,
    ByzantiumVM,
)
from evm.vm.forks.homestead.computation import (
    HomesteadComputation,
)
from evm.vm.forks.byzantium.computation import (
    ByzantiumComputation,
)
from evm.vm.forks.homestead.vm_state import HomesteadVMState
from evm.vm.forks.byzantium.vm_state import ByzantiumVMState
from evm.vm import (
    Message,
)

from evm.utils.fixture_tests import (
    normalize_vmtest_fixture,
    generate_fixture_tests,
    load_fixture,
    filter_fixtures,
    setup_state_db,
    verify_state_db,
    hash_log_entries,
)

from ethereum import utils


ROOT_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


BASE_FIXTURE_PATH = os.path.join(ROOT_PROJECT_DIR, 'fixtures', 'VMTests')


def vm_fixture_mark_fn(fixture_path, fixture_name):
    if fixture_path.startswith('vmPerformance'):
        return pytest.mark.skip('Performance tests are really slow')
    elif fixture_path == 'vmSystemOperations/createNameRegistrator.json':
        return pytest.mark.skip(
            'Skipped in go-ethereum due to failure without parallel processing'
        )


def pytest_generate_tests(metafunc):
    generate_fixture_tests(
        metafunc=metafunc,
        base_fixture_path=BASE_FIXTURE_PATH,
        filter_fn=filter_fixtures(
            fixtures_base_dir=BASE_FIXTURE_PATH,
            mark_fn=vm_fixture_mark_fn,
        )
    )


@pytest.fixture
def fixture(fixture_data):
    fixture_path, fixture_key = fixture_data
    fixture = load_fixture(
        fixture_path,
        fixture_key,
        normalize_vmtest_fixture,
    )
    return fixture


def get_block_hash_for_testing(self, block_number):
    if block_number >= self.block_number:
        return b''
    elif block_number < self.block_number - 256:
        return b''
    else:
        return keccak("{0}".format(block_number))


HomesteadComputationForTesting = HomesteadComputation.configure(
    name='HomesteadComputationForTesting',
    #apply_message=apply_message_for_testing,
    #apply_create_message=apply_create_message_for_testing,
)
HomesteadVMStateForTesting = HomesteadVMState.configure(
    name='HomesteadVMStateForTesting',
    #get_ancestor_hash=get_block_hash_for_testing,
    computation_class=HomesteadComputationForTesting,
)
HomesteadVMForTesting = HomesteadVM.configure(
    name='HomesteadVMForTesting',
    _state_class=HomesteadVMStateForTesting,
)
ByzantiumComputationForTesting = ByzantiumComputation.configure(
    name='ByzantiumComputationForTesting',
    #apply_message=apply_message_for_testing,
    #apply_create_message=apply_create_message_for_testing,
)
ByzantiumVMStateForTesting = ByzantiumVMState.configure(
    name='ByzantiumVMStateForTesting',
    #get_ancestor_hash=get_block_hash_for_testing,
    computation_class=ByzantiumComputationForTesting,
)
ByzantiumVMForTesting = ByzantiumVM.configure(
    name='ByzantiumVMForTesting',
    _state_class=ByzantiumVMStateForTesting,
)




@pytest.fixture(params=['Frontier', 'Homestead', 'EIP150', 'SpuriousDragon'])
def vm_class(request):
    if request.param == 'Frontier':
        pytest.skip('Only the Homestead VM rules are currently supported')
    elif request.param == 'Homestead':
        return ByzantiumVMForTesting
    elif request.param == 'EIP150':
        pytest.skip('Only the Homestead VM rules are currently supported')
    elif request.param == 'SpuriousDragon':
        pytest.skip('Only the Homestead VM rules are currently supported')
    else:
        assert False, "Unsupported VM: {0}".format(request.param)


def test_vm_fixtures(fixture, vm_class):
    chaindb = BaseChainDB(get_db_backend())
    header = BlockHeader(
        coinbase=fixture['env']['currentCoinbase'],
        difficulty=fixture['env']['currentDifficulty'],
        block_number=fixture['env']['currentNumber'],
        gas_limit=999999999999999999999999,
        timestamp=fixture['env']['currentTimestamp'],
    )
    vm = vm_class(header=header, chaindb=chaindb)
    TransactionClass = vm.get_transaction_class()
    vm_state = vm.state
    logger = logging.getLogger('evm')
    logger.setLevel(logging.TRACE)

    with vm_state.state_db() as state_db:
        setup_state_db(fixture['pre'], state_db)
    with vm_state.state_db() as state_db:
        code = state_db.get_code(fixture['exec']['address'])
        if len(code) == 0:
            return

        hex_code = utils.encode_hex(code)
        h = deployment.HydraDeployment(None, '/home/phil/py-evm/Hydra.sol', [])
        mc_code = h.format_meta_contract([fixture['exec']['address']], [], None, debug=False)

        creation_nonce = state_db.get_nonce(fixture['exec']['caller'])

        metacontract_address = generate_contract_address(
                fixture['exec']['caller'],
                creation_nonce,
        )

        try:
            instrumented_code = h.instrument_head(hex_code, 'evm', metacontract_address)
        except subprocess.CalledProcessError:
            return
        state_db.set_code(fixture['exec']['address'], instrumented_code)

        open('/tmp/1', 'w').write(mc_code)
        raw_output = check_output(['solc', '--combined-json', 'abi,bin', '/tmp/1'])
        output = json.loads(raw_output)
        contracts = [c['bin'] for c in output['contracts'].values() if c['abi'] != '[]']
        assert len(contracts) == 1
        mc_code = utils.decode_hex(contracts[0])

        # deploy MC and update state root manually
        vm.block.header.state_root = vm_state.state_root
        mc_create_tx = TransactionClass.create_unsigned_transaction(creation_nonce, 0, fixture['exec']['gas'] * 100000, CREATE_CONTRACT_ADDRESS, 0, mc_code)
        mc_create_tx.s = 1
        mc_create_tx.r = 1
        mc_create_tx.v = 1
        mc_create_tx.intrinsic_gas = 0
        mc_create_tx.sender = fixture['exec']['caller']
        computation, block = vm.apply_transaction(mc_create_tx)
        computation.apply_create_message()
        vm_state = vm.state
        #computation = vm.state.get_computation(message).apply_computation(
        #    vm.state,
        #    message,
        #)
        #computation.apply_create_message()
        #return
        #computation = vm.state.get_computation(message).apply_create_message() #.apply_computation(vm.state, message)
        #print("CLLLL", len(computation.children))


    with vm_state.state_db() as state_db:
        # Update state_root manually
        code = state_db.get_code(metacontract_address)
        for i in range(0, 50):
            print("STORN", i, state_db.get_storage(metacontract_address, i))
        #print("MC CODE OG", utils.encode_hex(mc_code))
        logger.debug('MC CODE DEPLOYED %s', utils.encode_hex(code))
        logger.debug('HEAD CODE DEPLOYED %s', utils.encode_hex(state_db.get_code(fixture['exec']['address'])))
        #print("MC CODE DEPLOYED", utils.encode_hex(code))
        #print("HEAD CODE DEPLOYED", utils.encode_hex(state_db.get_code(fixture['exec']['address'])))
        #print("MC PRECOMPUTE", utils.encode_hex(metacontract_address))
        #print("MC OUT", utils.encode_hex(computation.output))

    message = Message(
        origin=fixture['exec']['origin'],
        to=metacontract_address,
        sender=fixture['exec']['caller'],
        value=fixture['exec']['value'],
        data=fixture['exec']['data'],
        code=code,
        gas=fixture['exec']['gas'] * 1000000,
        gas_price=fixture['exec']['gasPrice'],
    )
    computation = vm.state.get_computation(message).apply_computation(
        vm.state,
        message,
    )
    # Update state_root manually
    vm.block.header.state_root = computation.vm_state.state_root

    if 'post' in fixture:
        #
        # Success checks
        #
        assert not computation.is_error

        log_entries = computation.get_log_entries()
        if 'logs' in fixture:
            actual_logs_hash = hash_log_entries(log_entries, log_override=fixture['exec']['address'])
            expected_logs_hash = fixture['logs']
            assert utils.encode_hex(expected_logs_hash) == utils.encode_hex(actual_logs_hash)
        elif log_entries:
            raise AssertionError("Got log entries: {0}".format(log_entries))

        expected_output = fixture['out']
        assert computation.output == expected_output

        gas_meter = computation.gas_meter

        expected_gas_remaining = fixture['gas']
        actual_gas_remaining = gas_meter.gas_remaining
        gas_delta = actual_gas_remaining - expected_gas_remaining
        open("gas_deltas", "a").write(str(gas_delta) + "\n")
        #assert gas_delta == 0, "Gas difference: {0}".format(gas_delta)

        call_creates = fixture.get('callcreates', [])
        assert len(computation.children) == len(call_creates) + 1

        call_creates = fixture.get('callcreates', [])
        for child_computation, created_call in zip(computation.children, call_creates):
            to_address = created_call['destination']
            data = created_call['data']
            gas_limit = created_call['gasLimit']
            value = created_call['value']

            assert child_computation.msg.to == to_address
            assert data == child_computation.msg.data or child_computation.msg.code
            #assert gas_limit == child_computation.msg.gas
            assert value == child_computation.msg.value
        post_state = fixture['post']
    else:
        #
        # Error checks
        #
        assert computation.is_error
        assert isinstance(computation._error, VMError)
        post_state = fixture['pre']

    #with vm.state.state_db(read_only=True) as state_db:
    #    verify_state_db(post_state, state_db)
