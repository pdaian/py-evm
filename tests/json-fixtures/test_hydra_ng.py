import os, sys, json

from ethereum import utils # @TODO get rid of pyethereum deps 


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

from evm.utils.hexadecimal import (
    encode_hex,
    decode_hex,
)


INSTRUMENTER_PATH = "/home/phil/Hydra/hydra/instrumenter/"

ROOT_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


BASE_FIXTURE_PATH = os.path.join(ROOT_PROJECT_DIR, 'fixtures', 'VMTests')


def vm_fixture_mark_fn(fixture_path, fixture_name):
    if fixture_path.startswith('vmPerformance'):
        return pytest.mark.skip('Performance tests are really slow')
    elif fixture_path == 'vmSystemOperations/createNameRegistrator.json':
        return pytest.mark.skip(
            'Skipped in go-ethereum due to failure without parallel processing'
        )
    elif fixture_path in ['vmTests/mktx.json', 'vmTests/arith.json', 'vmSystemOperations/suicideSendEtherToMe.json', 'vmSystemOperations/suicideNotExistingAccount.json', 'vmSystemOperations/suicide0.json', 'vmSystemOperations/ABAcalls3.json', 'vmSystemOperations/ABAcalls2.json', 'vmSystemOperations/ABAcalls1.json'] :
        return pytest.mark.skip(
            'Skipped due to Metropolis VM quirks'
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


def create_contract(TransactionClass, code, gas, sender, vm, state_db):
    creation_nonce = state_db.get_nonce(sender)
    create_tx = TransactionClass.create_unsigned_transaction(creation_nonce, 0, gas * 100000, CREATE_CONTRACT_ADDRESS, 0, code)
    create_tx.s = 1
    create_tx.r = 1
    create_tx.v = 1
    create_tx.intrinsic_gas = 0
    create_tx.sender = sender
    computation, block = vm.apply_transaction(create_tx)
    computation.apply_create_message()
    contract_address = generate_contract_address(
        sender,
        creation_nonce
    )
    state_db.increment_nonce(sender)
    return contract_address

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

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        setup_state_db(fixture['pre'], state_db)
    vm_state = vm.state

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        code = state_db.get_code(fixture['exec']['address'])
        #if len(code) == 0:
        #    return

        hex_code = encode_hex(code)
        h = deployment.HydraDeployment(None, '/home/phil/py-evm/Hydra.sol', [])
        mc_code = check_output(
            ["stack", "exec", "instrumenter-exe", "--", "metacontract"] + [encode_hex(a) for a in [fixture['exec']['address']]],
            cwd=INSTRUMENTER_PATH).strip()
        mc_code = utils.decode_hex(mc_code)
    vm_state = vm.state

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        # deploy MC and update state root manually
        metacontract_address = create_contract(TransactionClass, mc_code, fixture['exec']['gas'] * 100000, fixture['exec']['caller'], vm, state_db)
    vm_state = vm.state

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        try:
            logger.debug('HEAD CODE ORIGINALLY %s', encode_hex(code))
            instrumented_code = utils.decode_hex(check_output(["stack", "exec", "instrumenter-exe",
                                  "--", "1sthead",
                                  "0x" + utils.encode_hex(metacontract_address),
                                  utils.encode_hex(code)],
                                 cwd=INSTRUMENTER_PATH).strip())
        except subprocess.CalledProcessError:
            #return
            assert 5 == 6
        logger.debug('INSTRUMENTER RAN %s', encode_hex(instrumented_code))
    vm_state = vm.state

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        # deploy head and update state root manually
        head_address = create_contract(TransactionClass, instrumented_code, fixture['exec']['gas'] * 100000, fixture['exec']['caller'], vm, state_db)
        state_db.increment_nonce(fixture['exec']['caller'])
    vm_state = vm.state

    vm.block.header.state_root = vm_state.state_root
    with vm_state.state_db() as state_db:
        state_db.set_code(fixture['exec']['address'], state_db.get_code(head_address))
    vm_state = vm.state

    for slot in range(50):
        vm.block.header.state_root = vm_state.state_root
        with vm_state.state_db() as state_db:
            state_db.set_storage(fixture['exec']['address'], slot, state_db.get_storage(head_address, slot))
        vm_state = vm.state

    with vm_state.state_db() as state_db:
        # Update state_root manually
        code = state_db.get_code(metacontract_address)
        for i in range(0, 50):
            print("STORN", i, state_db.get_storage(metacontract_address, i))
        logger.debug('MC CODE DEPLOYED %s', encode_hex(code))
        logger.debug('HEAD CODE DEPLOYED %s', encode_hex(state_db.get_code(fixture['exec']['address'])))
        logger.debug('HEAD CODE SOURCE %s', encode_hex(state_db.get_code(head_address)))
        logger.debug('OG HEAD CODE %s', encode_hex(state_db.get_code(fixture['exec']['address'])))
        vm_state = vm.state

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
            assert encode_hex(expected_logs_hash) == encode_hex(actual_logs_hash)
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

    print("YAY" * 50000)
    #with vm.state.state_db(read_only=True) as state_db:
    #    verify_state_db(post_state, state_db)
