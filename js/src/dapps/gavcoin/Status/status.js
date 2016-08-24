import React, { Component, PropTypes } from 'react';

import { Toolbar, ToolbarGroup, ToolbarTitle } from 'material-ui/Toolbar';

const DIVISOR = 10 ** 6;

export default class Status extends Component {
  static propTypes = {
    address: PropTypes.string,
    blockNumber: PropTypes.object,
    totalSupply: PropTypes.object,
    remaining: PropTypes.object,
    price: PropTypes.object
  }

  render () {
    if (!this.props.totalSupply) {
      return null;
    }

    const { blockNumber, totalSupply, remaining, price } = this.props;

    return (
      <Toolbar className='status'>
        <ToolbarGroup>
          <ToolbarTitle text='GAVcoin' />
        </ToolbarGroup>
        <ToolbarGroup>
          <p>
            #{ blockNumber.toFormat() }: { this._formatCoin(remaining) } available @ { this._formatCoin(price, 0) }, { this._formatCoin(totalSupply) } minted
          </p>
        </ToolbarGroup>
      </Toolbar>
    );
  }

  _formatCoin (value, decimals = 6) {
    return value.div(DIVISOR).toFormat(decimals);
  }
}
