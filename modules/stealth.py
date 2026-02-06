"""Stealth and OpSec module for red team operations."""

import time
import random
import logging
from typing import Optional
from datetime import datetime, timedelta
import config


class StealthManager:
    """Manages operational security features for stealthy enumeration."""
    
    def __init__(self, stealth_enabled: bool = False):
        """
        Initialize stealth manager.
        
        Args:
            stealth_enabled: Enable stealth features
        """
        self.enabled = stealth_enabled or config.STEALTH_SETTINGS['enabled']
        self.logger = logging.getLogger(__name__)
        
        # Query tracking for rate limiting
        self.query_count = 0
        self.last_query_time = None
        self.session_start = datetime.now()
        self.queries_this_minute = 0
        self.minute_start = datetime.now()
        
        if self.enabled:
            self.logger.info("Stealth mode ENABLED - Using OpSec features")
            self._log_stealth_config()
        else:
            self.logger.info("Stealth mode DISABLED - Full speed enumeration")
    
    def wait_before_query(self):
        """
        Apply intelligent delay before next query.
        
        Uses configurable delays with jitter to blend with normal traffic.
        """
        if not self.enabled:
            return
        
        # Check rate limiting
        self._enforce_rate_limit()
        
        # Calculate delay with jitter
        delay = self._calculate_delay()
        
        if delay > 0:
            self.logger.debug(f"OpSec delay: {delay:.2f}s")
            time.sleep(delay)
        
        # Update tracking
        self.last_query_time = datetime.now()
        self.query_count += 1
        self.queries_this_minute += 1
    
    def get_page_size(self) -> int:
        """
        Get appropriate page size based on stealth mode.
        
        Returns:
            Page size for LDAP queries
        """
        if self.enabled:
            # Use smaller page size to avoid large bulk queries
            return config.STEALTH_SETTINGS['page_size_stealth']
        else:
            return config.LDAP_SETTINGS['page_size']
    
    def should_randomize_queries(self) -> bool:
        """Check if query order should be randomized."""
        return self.enabled and config.STEALTH_SETTINGS['randomize_query_order']
    
    def get_session_stats(self) -> dict:
        """
        Get statistics about the current enumeration session.
        
        Returns:
            Dictionary with session statistics
        """
        elapsed = datetime.now() - self.session_start
        
        return {
            'total_queries': self.query_count,
            'elapsed_time': str(elapsed),
            'queries_per_minute': self.query_count / max(elapsed.total_seconds() / 60, 1),
            'stealth_enabled': self.enabled,
        }
    
    def delay_for_spread(self, total_items: int, item_index: int):
        """
        Calculate delay to spread enumeration over configured time.
        
        Args:
            total_items: Total number of items to enumerate
            item_index: Current item index
        """
        spread_hours = config.STEALTH_SETTINGS['spread_enumeration_hours']
        
        if not self.enabled or spread_hours == 0:
            return
        
        # Calculate delay to spread evenly
        total_seconds = spread_hours * 3600
        delay_per_item = total_seconds / max(total_items, 1)
        
        # Add to regular delay
        additional_delay = delay_per_item * (item_index + 1)
        elapsed = (datetime.now() - self.session_start).total_seconds()
        
        if additional_delay > elapsed:
            sleep_time = additional_delay - elapsed
            self.logger.debug(f"Spread delay: {sleep_time:.2f}s ({item_index+1}/{total_items})")
            time.sleep(sleep_time)
    
    def _calculate_delay(self) -> float:
        """
        Calculate delay with jitter.
        
        Returns:
            Delay in seconds
        """
        min_delay = config.STEALTH_SETTINGS['query_delay_min']
        max_delay = config.STEALTH_SETTINGS['query_delay_max']
        
        # Base delay (random between min and max)
        base_delay = random.uniform(min_delay, max_delay)
        
        # Apply jitter if enabled
        if config.STEALTH_SETTINGS['jitter_enabled']:
            jitter_pct = config.STEALTH_SETTINGS['jitter_percentage'] / 100.0
            jitter = base_delay * jitter_pct * random.uniform(-1, 1)
            delay = base_delay + jitter
        else:
            delay = base_delay
        
        return max(0, delay)  # Ensure non-negative
    
    def _enforce_rate_limit(self):
        """Enforce queries-per-minute rate limit."""
        max_qpm = config.STEALTH_SETTINGS['max_queries_per_minute']
        
        # Check if we need to reset the minute counter
        elapsed = (datetime.now() - self.minute_start).total_seconds()
        if elapsed >= 60:
            self.queries_this_minute = 0
            self.minute_start = datetime.now()
            return
        
        # If we've hit the limit, wait until the minute resets
        if self.queries_this_minute >= max_qpm:
            wait_time = 60 - elapsed
            self.logger.debug(f"Rate limit reached ({max_qpm} QPM), waiting {wait_time:.1f}s")
            time.sleep(wait_time)
            self.queries_this_minute = 0
            self.minute_start = datetime.now()
    
    def _log_stealth_config(self):
        """Log current stealth configuration."""
        self.logger.info("OpSec Configuration:")
        self.logger.info(f"  Query Delay: {config.STEALTH_SETTINGS['query_delay_min']}-{config.STEALTH_SETTINGS['query_delay_max']}s")
        self.logger.info(f"  Jitter: {'Enabled' if config.STEALTH_SETTINGS['jitter_enabled'] else 'Disabled'}")
        self.logger.info(f"  Rate Limit: {config.STEALTH_SETTINGS['max_queries_per_minute']} queries/min")
        self.logger.info(f"  Page Size: {config.STEALTH_SETTINGS['page_size_stealth']}")
        self.logger.info(f"  Query Randomization: {'Enabled' if config.STEALTH_SETTINGS['randomize_query_order'] else 'Disabled'}")
        
        if config.STEALTH_SETTINGS['spread_enumeration_hours'] > 0:
            self.logger.info(f"  Spread Duration: {config.STEALTH_SETTINGS['spread_enumeration_hours']} hours")


class QueryRandomizer:
    """Randomize query order to avoid predictable patterns."""
    
    @staticmethod
    def randomize_list(items: list) -> list:
        """
        Randomize list order if stealth mode enabled.
        
        Args:
            items: List to randomize
        
        Returns:
            Randomized or original list
        """
        if config.STEALTH_SETTINGS['randomize_query_order']:
            shuffled = items.copy()
            random.shuffle(shuffled)
            return shuffled
        return items
    
    @staticmethod
    def randomize_attributes(attributes: list) -> list:
        """
        Randomize attribute order in queries.
        
        Args:
            attributes: List of attributes
        
        Returns:
            Randomized or original list
        """
        if config.STEALTH_SETTINGS['randomize_query_order']:
            shuffled = attributes.copy()
            random.shuffle(shuffled)
            return shuffled
        return attributes
