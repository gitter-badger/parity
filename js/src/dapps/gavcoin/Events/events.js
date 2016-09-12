import React, { Component, PropTypes } from 'react';

import EventBuyin from './EventBuyin';
import EventNewTranch from './EventNewTranch';
import EventRefund from './EventRefund';
import EventTransfer from './EventTransfer';

import styles from './events.css';

export default class Events extends Component {
  static childContextTypes = {
    accounts: PropTypes.array
  }

  static contextTypes = {
    contract: PropTypes.object.isRequired,
    instance: PropTypes.object.isRequired
  }

  static propTypes = {
    accounts: PropTypes.array
  }

  state = {
    allEvents: [],
    minedEvents: [],
    pendingEvents: []
  }

  componentDidMount () {
    this.setupFilters();
  }

  render () {
    return (
      <div className={ styles.events }>
        <table className={ styles.list }>
          <tbody>
            { this.renderEvents() }
          </tbody>
        </table>
      </div>
    );
  }

  renderEvents () {
    const { allEvents } = this.state;

    if (!allEvents.length) {
      return null;
    }

    return allEvents
      .map((event) => {
        switch (event.type) {
          case 'Buyin':
            return <EventBuyin key={ event.key } event={ event } />;
          case 'NewTranch':
            return <EventNewTranch key={ event.key } event={ event } />;
          case 'Refund':
            return <EventRefund key={ event.key } event={ event } />;
          case 'Transfer':
            return <EventTransfer key={ event.key } event={ event } />;
        }
      });
  }

  getChildContext () {
    const { accounts } = this.props;

    return {
      accounts
    };
  }

  setupFilters () {
    const { contract } = this.context;
    let key = 0;

    const sortEvents = (a, b) => b.blockNumber.cmp(a.blockNumber) || b.logIndex.cmp(a.logIndex);
    const logToEvent = (eventName, log) => {
      const { blockNumber, logIndex, transactionHash, transactionIndex, params, type } = log;

      return {
        type: eventName,
        state: type,
        blockNumber,
        logIndex,
        transactionHash,
        transactionIndex,
        params,
        key: ++key
      };
    };

    const options = {
      fromBlock: 0,
      toBlock: 'pending'
    };

    contract.subscribe(null, options, (error, logs) => {
      if (error) {
        console.error('setupFilters', error);
        return;
      }

      if (!logs.length) {
        return;
      }

      console.log(logs);

      const minedEvents = logs
        .filter((log) => log.type === 'mined')
        .map((log) => logToEvent(log.event, log))
        .reverse()
        .concat(this.state.minedEvents)
        .sort(sortEvents);
      const pendingEvents = logs
        .filter((log) => log.type === 'pending')
        .map((log) => logToEvent(log.event, log))
        .reverse()
        .concat(this.state.pendingEvents.filter((event) => {
          return !logs.find((log) => {
            return (log.type === 'mined') && (log.transactionHash === event.transactionHash);
          });
        }))
        .sort(sortEvents);
      const allEvents = pendingEvents.concat(minedEvents);

      this.setState({
        allEvents,
        minedEvents,
        pendingEvents
      });
    });
  }
}