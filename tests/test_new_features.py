import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import numpy as np

from sqli_hunter.exploiter import Exploiter
from sqli_hunter.waf_detector import WafDetector, BOOST_MODEL
from sqli_hunter.polymorphic_engine import PolymorphicEngine, QAOAOptimizer

# Mock data for testing
@pytest.fixture
def mock_browser_context():
    """Provides a mock Playwright browser context."""
    return AsyncMock()

@pytest.fixture
def mock_vuln_details():
    """Provides a sample vulnerability detail dictionary."""
    return {
        "url": "http://test.com",
        "method": "POST",
        "parameter": "username",
        "request_data": {"data": {"username": "", "password": ""}},
    }

@pytest.mark.asyncio
async def test_quic_exfiltration_simulation(mock_browser_context, mock_vuln_details, mocker):
    """
    Tests that the QUIC exfiltration method attempts to start a server and client.
    """
    # Mock the networking functions to avoid real network I/O
    mock_server = AsyncMock()
    mock_server.close.return_value = None
    mock_server.wait_closed.return_value = asyncio.sleep(0)

    mock_connect_cm = AsyncMock() # This is the context manager
    mock_connect_cm.__aenter__.return_value = AsyncMock() # This is the client

    mocker.patch("sqli_hunter.exploiter.serve", return_value=mock_server)
    mocker.patch("sqli_hunter.exploiter.connect", return_value=mock_connect_cm)

    exploiter = Exploiter(mock_browser_context)
    # The method will now run without network errors, but won't return data as the futures are not resolved
    # We are testing that the logic to set up the server/client is called.
    await exploiter.extract_data_quic(AsyncMock(), mock_vuln_details, "test_cache_key")

    # Assert that our mocks were used
    assert mock_server.close.called
    assert mock_connect_cm.__aenter__.called


def test_polymorphic_engine_with_diffusion():
    """
    Tests that the diffusion model generates different and plausible payloads.
    """
    engine = PolymorphicEngine()
    base_payload = "' OR 1=1 --"
    variations = engine.generate(base_payload, num_variations=5, use_diffusion=True)

    assert len(variations) > 0
    assert all(isinstance(v, str) for v in variations)
    # Check that they contain some SQL-like keywords, not just garbage
    assert any("select" in v or "union" in v or "or" in v for v in variations)

def test_qaoa_optimizer_scoring():
    """
    Tests that the QAOA optimizer's internal scoring function correctly
    identifies the most promising payload based on heuristics.
    """
    # Payload 3 should have the highest score (length + diversity + keywords)
    payloads = [
        "1' OR '1'='1",
        "a b c d e f g",
        "' UNION SELECT 1,2,3 -- ",
    ]

    optimizer = QAOAOptimizer(payloads)
    scores = optimizer._score_payloads()
    best_index_by_score = np.argmax(scores)

    assert payloads[best_index_by_score] == "' UNION SELECT 1,2,3 -- "
