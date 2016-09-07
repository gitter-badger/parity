import React, { Component, PropTypes } from 'react';
import { connect } from 'react-redux';
import { bindActionCreators } from 'redux';

import styles from './status.css';

class Status extends Component {
  static propTypes = {
    blockNumber: PropTypes.object,
    clientVersion: PropTypes.string,
    netPeers: PropTypes.object,
    netChain: PropTypes.string,
    isTest: PropTypes.bool
  }

  render () {
    const { clientVersion, blockNumber, netChain, netPeers, isTest } = this.props;
    const netStyle = `${styles.network} ${styles[isTest ? 'networktest' : 'networklive']}`;

    if (!blockNumber) {
      return null;
    }

    return (
      <div className={ styles.status }>
        <div className={ styles.version }>
          { clientVersion }
        </div>
        <div className={ styles.netinfo }>
          <div>
            <div className={ styles.block }>
              { blockNumber.toFormat() } blocks
            </div>
            <div className={ styles.peers }>
              { netPeers.active.toFormat() }/{ netPeers.connected.toFormat() }/{ netPeers.max.toFormat() } peers
            </div>
          </div>
          <div className={ netStyle }>
            { isTest ? 'test' : netChain }
          </div>
        </div>
      </div>
    );
  }
}

function mapStateToProps (state) {
  const { blockNumber, clientVersion, netPeers, netChain, isTest } = state.status;

  return {
    blockNumber,
    clientVersion,
    netPeers,
    netChain,
    isTest
  };
}

function mapDispatchToProps (dispatch) {
  return bindActionCreators({}, dispatch);
}

export default connect(
  mapStateToProps,
  mapDispatchToProps
)(Status);