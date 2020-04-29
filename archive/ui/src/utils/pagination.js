/**
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

var perPage = 50;

function populatePages(baseUri, currentPage, totalItemsCount) {
  currentPage = (+currentPage > 0) ? +currentPage : 1;
  var currentPageTotal = currentPage * perPage,
    isFirstPage = currentPage <= 1,
    isLastPage = currentPageTotal >= totalItemsCount,
    output = {
      firstPage: '',
      lastPage: '',
      nextPage: '',
      previousPage: '',
      totalItemsCount: 0,
      startItemIndex: 0,
      endItemIndex: 0
    };

  if (!isFirstPage) {
    output.firstPage = baseUri + '1';
    output.previousPage = baseUri + (currentPage - 1);
  }

  if (!isLastPage) {
    output.lastPage = baseUri + Math.ceil(totalItemsCount / perPage);
    output.nextPage = baseUri + (currentPage + 1);
  }

  if(totalItemsCount) {
    var startIndex = ((currentPage - 1) * perPage) + 1;
    var itemsInPage = (startIndex - 1 + perPage <= totalItemsCount) ? perPage :  totalItemsCount % perPage;
    output.startItemIndex = startIndex;
    output.endItemIndex = startIndex + itemsInPage - 1;
    output.totalItems = totalItemsCount;
  }

  return output;
}

function populateQueryParams(currentPage) {
  if (currentPage === 'all') {
    return {
      start: 0,
      count: 1000000
    };
  }

  currentPage = (+currentPage > 0) ? +currentPage : 1;
  return {
    start: (currentPage - 1) * perPage,
    count: perPage
  };
}

module.exports = {
  perPage: perPage,
  populatePages: populatePages,
  populateQueryParams: populateQueryParams
};
